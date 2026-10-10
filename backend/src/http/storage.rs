//! `/blobs` and `/refs` (SPEC §7, §8.4, §8.5). Every query takes the user from the session.

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use super::guard::Authed;
use super::{ApiError, AppState, json_body, read_body, unsupported_media_type};
use crate::domain::{
    BlobId, ByteRange, etag, format_timestamp, page_limit, parse_precondition, parse_range,
    valid_ref_name,
};
use crate::store::{self, BlobDeletion, BlobMeta, RefDeletion, RefRow, RefWrite};

const PAGE_MAX: usize = 1000;

fn blob_id(s: &str) -> Result<BlobId, ApiError> {
    BlobId::parse(s)
        .ok_or_else(|| ApiError::bad_request("A blob ID is 64 lowercase hex characters"))
}

fn ref_name(name: &str) -> Result<String, ApiError> {
    valid_ref_name(name)
        .then(|| name.to_owned())
        .ok_or_else(|| ApiError::bad_request("Invalid ref name"))
}

fn blob_json(meta: &BlobMeta) -> Value {
    json!({ "id": meta.id.to_string(), "size": meta.size, "created_at": format_timestamp(meta.created_at) })
}

fn ref_json(row: &RefRow) -> Value {
    json!({ "name": row.name, "blob": row.blob.to_string(), "updated_at": format_timestamp(row.updated_at) })
}

fn precondition_failed(current: Option<BlobId>) -> ApiError {
    ApiError::new(
        StatusCode::PRECONDITION_FAILED,
        "precondition_failed",
        "The ref is not in the expected state",
    )
    .with(
        "current",
        current.map_or(Value::Null, |id| Value::from(id.to_string())),
    )
}

/// Splits one extra item off a `limit + 1` query: the page, and the cursor for the next one.
fn paginate<T, K>(mut items: Vec<T>, limit: usize, key: impl Fn(&T) -> K) -> (Vec<T>, Option<K>) {
    let more = items.len() > limit;
    items.truncate(limit);
    let next = more.then(|| items.last().map(key)).flatten();
    (items, next)
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

// ---------------------------------------------------------------- blobs

#[derive(Deserialize)]
pub struct BlobPage {
    after: Option<String>,
    limit: Option<usize>,
}

pub async fn list_blobs(
    State(state): State<AppState>,
    authed: Authed,
    Query(q): Query<BlobPage>,
) -> Result<Json<Value>, ApiError> {
    let after = q.after.as_deref().map(blob_id).transpose()?;
    let limit = page_limit(q.limit, PAGE_MAX);
    let user_id = authed.session.user_id;
    let rows = state
        .db(move |c| store::list_blobs(c, &user_id, after, limit))
        .await?;
    let (page, next) = paginate(rows, limit, |m| m.id.to_string());
    Ok(Json(
        json!({ "blobs": page.iter().map(blob_json).collect::<Vec<_>>(), "next": next }),
    ))
}

pub async fn put_blob(
    State(state): State<AppState>,
    authed: Authed,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let id = blob_id(&id)?;
    let is_octet_stream = header_str(&headers, header::CONTENT_TYPE)
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/octet-stream"));
    if !is_octet_stream {
        return Err(unsupported_media_type("application/octet-stream"));
    }
    let content = read_body(body, state.config.max_blob_size).await?;
    if BlobId::of(&content) != id {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "hash_mismatch",
            "The content's SHA-256 doesn't match the blob ID",
        ));
    }
    let user_id = authed.session.user_id;
    let now = state.now();
    let (created, meta) = state
        .db(move |c| store::put_blob(c, &user_id, id, &content, now))
        .await?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(blob_json(&meta))).into_response())
}

/// GET and HEAD (axum answers HEAD with the GET handler and drops the body).
pub async fn get_blob(
    State(state): State<AppState>,
    authed: Authed,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = blob_id(&id)?;
    let user_id = authed.session.user_id;
    let (meta, content) = state
        .db(move |c| store::blob_content(c, &user_id, id))
        .await?
        .ok_or_else(ApiError::not_found)?;
    let size = meta.size;
    let (status, body, content_range) = match parse_range(header_str(&headers, header::RANGE), size)
    {
        ByteRange::Full => (StatusCode::OK, content, None),
        ByteRange::Partial { start, end } => {
            let slice = content
                [usize::try_from(start).unwrap_or(0)..=usize::try_from(end).unwrap_or(0)]
                .to_vec();
            (
                StatusCode::PARTIAL_CONTENT,
                slice,
                Some(format!("bytes {start}-{end}/{size}")),
            )
        }
        ByteRange::Unsatisfiable => {
            let mut error = ApiError::new(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "range_not_satisfiable",
                "The range is outside the blob",
            )
            .into_response();
            error.headers_mut().insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes */{size}")).map_err(ApiError::internal)?,
            );
            return Ok(error);
        }
    };
    let mut response = (status, body).into_response();
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(
        header::ETAG,
        HeaderValue::from_str(&etag(meta.id)).map_err(ApiError::internal)?,
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    if let Some(range) = content_range {
        h.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&range).map_err(ApiError::internal)?,
        );
    }
    Ok(response)
}

pub async fn delete_blob(
    State(state): State<AppState>,
    authed: Authed,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = blob_id(&id)?;
    let user_id = authed.session.user_id;
    match state
        .db(move |c| store::delete_blob(c, &user_id, id))
        .await?
    {
        BlobDeletion::Deleted => Ok(StatusCode::NO_CONTENT.into_response()),
        BlobDeletion::NotFound => Err(ApiError::not_found()),
        BlobDeletion::Referenced => Err(ApiError::new(
            StatusCode::CONFLICT,
            "blob_referenced",
            "A ref still points to this blob",
        )),
    }
}

// ---------------------------------------------------------------- refs

#[derive(Deserialize)]
pub struct RefPage {
    prefix: Option<String>,
    after: Option<String>,
    limit: Option<usize>,
}

pub async fn list_refs(
    State(state): State<AppState>,
    authed: Authed,
    Query(q): Query<RefPage>,
) -> Result<Json<Value>, ApiError> {
    let limit = page_limit(q.limit, PAGE_MAX);
    let prefix = q.prefix.unwrap_or_default();
    let after = q.after.unwrap_or_default();
    let user_id = authed.session.user_id;
    let rows = state
        .db(move |c| store::list_refs(c, &user_id, &prefix, &after, limit))
        .await?;
    let (page, next) = paginate(rows, limit, |r| r.name.clone());
    Ok(Json(
        json!({ "refs": page.iter().map(ref_json).collect::<Vec<_>>(), "next": next }),
    ))
}

pub async fn get_ref(
    State(state): State<AppState>,
    authed: Authed,
    Path(name): Path<String>,
) -> Result<Response, ApiError> {
    let name = ref_name(&name)?;
    let user_id = authed.session.user_id;
    let row = state
        .db(move |c| store::get_ref(c, &user_id, &name))
        .await?
        .ok_or_else(ApiError::not_found)?;
    let mut response = Json(ref_json(&row)).into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&etag(row.blob)).map_err(ApiError::internal)?,
    );
    Ok(response)
}

#[derive(Deserialize)]
struct RefTarget {
    blob: String,
}

pub async fn put_ref(
    State(state): State<AppState>,
    authed: Authed,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let name = ref_name(&name)?;
    let precondition = parse_precondition(
        header_str(&headers, header::IF_MATCH),
        header_str(&headers, header::IF_NONE_MATCH),
        true,
    )
    .map_err(|_| ApiError::bad_request("Unsupported precondition headers"))?;
    let RefTarget { blob } = json_body(&headers, body).await?;
    let blob = blob_id(&blob)?;
    let user_id = authed.session.user_id;
    let now = state.now();
    match state
        .db(move |c| store::put_ref(c, &user_id, &name, blob, precondition, now))
        .await?
    {
        RefWrite::Created(row) => Ok((StatusCode::CREATED, Json(ref_json(&row))).into_response()),
        RefWrite::Updated(row) => Ok((StatusCode::OK, Json(ref_json(&row))).into_response()),
        RefWrite::PreconditionFailed(current) => Err(precondition_failed(current)),
        RefWrite::BlobNotFound => Err(ApiError::new(
            StatusCode::CONFLICT,
            "blob_not_found",
            "The target blob doesn't exist",
        )),
    }
}

pub async fn delete_ref(
    State(state): State<AppState>,
    authed: Authed,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let name = ref_name(&name)?;
    let precondition = parse_precondition(
        header_str(&headers, header::IF_MATCH),
        header_str(&headers, header::IF_NONE_MATCH),
        false,
    )
    .map_err(|_| ApiError::bad_request("Unsupported precondition headers"))?;
    let user_id = authed.session.user_id;
    match state
        .db(move |c| store::delete_ref(c, &user_id, &name, precondition))
        .await?
    {
        RefDeletion::Deleted => Ok(StatusCode::NO_CONTENT.into_response()),
        RefDeletion::NotFound => Err(ApiError::not_found()),
        RefDeletion::PreconditionFailed(current) => Err(precondition_failed(current)),
    }
}

#[cfg(test)]
mod tests {
    use super::paginate;

    #[test]
    fn pagination_uses_the_extra_item_as_the_signal() {
        assert_eq!(paginate(vec![1, 2, 3], 2, |x| *x), (vec![1, 2], Some(2)));
        assert_eq!(paginate(vec![1, 2], 2, |x| *x), (vec![1, 2], None));
        assert_eq!(paginate(Vec::<i32>::new(), 2, |x| *x), (vec![], None));
    }
}
