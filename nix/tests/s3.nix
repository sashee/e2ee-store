# The stand-in app (./demo-module.nix) with S3 backends (backend SPEC §7.4): the instance gets one credential file per backend, encrypted by
# systemd, and talks to Garage on the same machine, behind nginx for TLS with a test CA in the system's bundle. Two
# backends, a bucket each. On top of the checks of ./lib.nix: offloadable blobs go to S3, read back through the API,
# and move when the targets change, between the database and a backend and from one backend to the other; with a copy
# in each of several targets, an emptied bucket is filled again, and one whose bucket is gone is emptied but, still
# configured, not forgotten;
# the credentials stay the service's; and against a real S3, the sweep, an outage and a lost object.
#
# `machineModules` are the machine's own configuration, as for ./lib.nix: a host repository passes its real one.
{
  pkgs,
  machineModules,
}:
let
  inherit (pkgs) lib;

  # A CA and a certificate for localhost signed by it: nginx serves it, the backend trusts the CA.
  certs = pkgs.runCommand "e2ee-store-test-certs" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir -p "$out"
    key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }
    key ca.key
    openssl req -x509 -new -key ca.key -days 3650 -subj /CN=test-ca \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
      -out "$out/ca.crt"
    key "$out/private.key"
    openssl req -new -key "$out/private.key" -subj /CN=localhost -out leaf.csr
    printf '%s\n' basicConstraints=CA:FALSE extendedKeyUsage=serverAuth subjectAltName=DNS:localhost,IP:127.0.0.1 > leaf.ext
    openssl x509 -req -in leaf.csr -CA "$out/ca.crt" -CAkey ca.key -CAcreateserial -days 3650 -extfile leaf.ext \
      -out "$out/public.crt"
  '';

  # Garage's key format: GK and 24 hex digits, and 64 hex digits. Imported into Garage by the test.
  keyId = "GK0123456789abcdef01234567";
  secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

  # A backend's plaintext credential file. In the store here, as it's a test's; on a host it only exists encrypted.
  credentialFile =
    bucket:
    pkgs.writeText "${bucket}.toml" ''
      endpoint = "https://localhost:9000"
      region = "garage"
      bucket = "${bucket}"
      prefix = "demo/"
      access_key_id = "${keyId}"
      secret_access_key = "${secret}"
    '';
  # Backend name → bucket.
  backends = {
    garage = "blobs";
    garage2 = "blobs2";
  };
in
import ./lib.nix {
  inherit pkgs;
  instance = "demo";
  machineModules = machineModules ++ [
    ./demo-module.nix
    {
      virtualisation.memorySize = lib.mkDefault 2048;
      # Garage wants at least 1 GiB free.
      virtualisation.diskSize = lib.mkDefault 2048;
      security.pki.certificateFiles = [ "${certs}/ca.crt" ];
      environment.systemPackages = [ pkgs.minio-client ];

      services.garage = {
        enable = true;
        package = pkgs.garage;
        settings = {
          rpc_bind_addr = "127.0.0.1:3901";
          rpc_public_addr = "127.0.0.1:3901";
          rpc_secret = "5c1915fa04d0b6739675c61bf5907eb0fe3d9c69850c83820f51b4d25d13868c";
          s3_api = {
            s3_region = "garage";
            api_bind_addr = "[::1]:3900";
          };
        }
        // (
          if lib.versionAtLeast pkgs.garage.version "2" then
            {
              replication_factor = 1;
              consistency_mode = "consistent";
            }
          else
            { replication_mode = "none"; }
        );
      };

      services.nginx = {
        enable = true;
        virtualHosts.localhost = {
          onlySSL = true;
          listen = [
            {
              addr = "127.0.0.1";
              port = 9000;
              ssl = true;
            }
          ];
          sslCertificate = "${certs}/public.crt";
          sslCertificateKey = "${certs}/private.key";
          locations."/" = {
            proxyPass = "http://[::1]:3900";
            # The client signs the Host it sent, port included.
            extraConfig = ''
              proxy_set_header Host $host:$server_port;
              client_max_body_size 64m;
            '';
          };
        };
      };

      services.demo = {
        enable = true;
        settings.blob_target = [ "garage" ];
        storageBackends = lib.mapAttrs (name: _: {
          type = "s3";
          credentialFile = "/etc/credentials/demo/${name}";
        }) backends;
      };

      # What an admin does once on a host, as a unit: encrypt the credential file with the host's key.
      systemd.services.demo-s3-credential = {
        requiredBy = [ "demo.service" ];
        before = [ "demo.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          install -d -m 0700 /etc/credentials/demo
          ${lib.concatStrings (
            lib.mapAttrsToList (name: bucket: ''
              ${pkgs.systemd}/bin/systemd-creds encrypt --name=${name} ${credentialFile bucket} /etc/credentials/demo/${name}
            '') backends
          )}
        '';
      };
    }
  ];
  extraTestScript = ''
    import re

    API = f"curl -sf --unix-socket {SOCKET} -H 'Origin: http://localhost' -b /tmp/jar -c /tmp/jar"


    def objects(bucket="blobs"):
        return machine.succeed(f"mc ls --recursive s3/{bucket}")


    def restart():
        # This test restarts more often than systemd's start limit allows (5 in 10 s); `reset-failed` resets the
        # count. A service restarting by itself waits 5 s, so it can't reach the limit.
        machine.systemctl(f"reset-failed {NAME}.service")
        machine.systemctl(f"restart {NAME}.service")
        wait_until_serving()


    def status(blob):
        """The HTTP status of reading the blob."""
        return machine.succeed(
            f"curl -s -o /dev/null -w '%{{http_code}}' --unix-socket {SOCKET} -b /tmp/jar "
            f"http://localhost/api/v1/blobs/{blob}"
        )


    def upload(path):
        """Uploads the file as an offloadable blob; → its ID."""
        blob = machine.succeed(f"sha256sum {path}").split()[0]
        uploaded = machine.succeed(
            f"{API} -X PUT -H 'Content-Type: application/octet-stream' -H 'Blob-Offloadable: true' "
            f"--data-binary @{path} http://localhost/api/v1/blobs/{blob}"
        )
        assert '"offloadable":true' in uploaded, uploaded
        return blob


    with subtest("S3 is up: a one-node Garage with a bucket and the instance's key"):
        machine.wait_for_unit("garage.service")
        machine.wait_for_open_port(3900)
        machine.wait_for_open_port(3901)
        node = machine.succeed("garage node id -q").strip().split("@")[0]
        machine.succeed(f"garage layout assign -z vm -c 1G {node}")
        machine.succeed("garage layout apply --version 1")
        machine.succeed("garage key import --yes -n demo ${keyId} ${secret}")
        for bucket in ["blobs", "blobs2"]:
            machine.succeed(f"garage bucket create {bucket}")
            machine.succeed(f"garage bucket allow --read --write {bucket} --key demo")
        machine.wait_for_unit("nginx.service")
        machine.succeed("mc alias set s3 https://localhost:9000 ${keyId} ${secret} --api S3v4")

    with subtest("offloadable blobs go to S3, and read back from there"):
        link = re.search(r"#setup=(\S+)", machine.succeed(f"{NAME} setup-token create alice"))
        assert link, "the CLI prints a setup link"
        token = link.group(1)
        machine.succeed(
            f"{API} -H 'Content-Type: application/json' -d '{{\"token\": \"{token}\"}}' "
            "http://localhost/api/v1/auth/setup-token"
        )
        machine.succeed("head -c 100000 /dev/urandom > /tmp/track")
        blob = upload("/tmp/track")
        assert re.search(rf"demo/[0-9a-f-]+/{blob}", objects()), objects()
        machine.succeed(f"{API} -o /tmp/whole http://localhost/api/v1/blobs/{blob} && cmp /tmp/track /tmp/whole")
        machine.succeed(
            f"{API} -r 1000-1999 -o /tmp/part http://localhost/api/v1/blobs/{blob} "
            "&& cmp -i 1000:0 -n 1000 /tmp/track /tmp/part && test $(stat -c %s /tmp/part) = 1000"
        )

    with subtest("changing the target moves them back, and out again"):
        machine.succeed("systemctl set-environment BACKEND_BLOB_TARGET=local")
        restart()
        machine.wait_until_succeeds(f"! mc ls --recursive s3/blobs | grep -q {blob}")
        machine.succeed(f"{API} -o /tmp/whole http://localhost/api/v1/blobs/{blob} && cmp /tmp/track /tmp/whole")
        machine.succeed("systemctl unset-environment BACKEND_BLOB_TARGET")
        restart()
        machine.wait_until_succeeds(f"mc ls --recursive s3/blobs | grep -q {blob}")
        machine.succeed(f"{API} -o /tmp/whole http://localhost/api/v1/blobs/{blob} && cmp /tmp/track /tmp/whole")

    with subtest("from one backend to another, without the database"):
        machine.succeed("systemctl set-environment BACKEND_BLOB_TARGET=garage2")
        restart()
        machine.wait_until_succeeds(f"mc ls --recursive s3/blobs2 | grep -q {blob}")
        machine.wait_until_succeeds(f"! mc ls --recursive s3/blobs | grep -q {blob}")
        machine.succeed(f"{API} -o /tmp/whole http://localhost/api/v1/blobs/{blob} && cmp /tmp/track /tmp/whole")
        report = machine.succeed(f"{NAME} storage")
        # The admin command reads the configuration as written: the override is the service's alone.
        assert re.search(r"^garage2\s+1\s", report, re.M), report
        machine.succeed("systemctl unset-environment BACKEND_BLOB_TARGET")
        restart()
        machine.wait_until_succeeds(f"mc ls --recursive s3/blobs | grep -q {blob}")
        machine.wait_until_succeeds(f"! mc ls --recursive s3/blobs2 | grep -q {blob}")

    with subtest("a copy in each target: the database and both backends"):
        machine.succeed("systemctl set-environment BACKEND_BLOB_TARGET=local,garage,garage2")
        restart()
        machine.wait_until_succeeds(f"mc ls --recursive s3/blobs2 | grep -q {blob}")
        assert blob in objects(), objects()
        report = machine.succeed(f"{NAME} storage")
        assert re.search(r"^local\s+1\s", report, re.M), report
        assert "by copies: 1 with 3" in report, report

    with subtest("a bucket emptied behind the server's back is filled again"):
        machine.succeed("mc rm --recursive --force s3/blobs2/demo/")
        assert blob not in objects("blobs2")
        restart()
        machine.wait_until_succeeds(f"mc ls --recursive s3/blobs2 | grep -q {blob}")
        machine.succeed(f"{API} -o /tmp/whole http://localhost/api/v1/blobs/{blob} && cmp /tmp/track /tmp/whole")

    with subtest("a backend whose bucket is gone: out of the targets, its copies go; configured, it isn't forgotten"):
        machine.systemctl(f"stop {NAME}.service")
        machine.succeed("mc rm --recursive --force s3/blobs2/demo/")
        machine.succeed("garage bucket delete --yes blobs2")
        machine.succeed("systemctl set-environment BACKEND_BLOB_TARGET=local,garage")
        restart()
        machine.wait_until_succeeds(f"! {NAME} storage | grep -q '^garage2 '")
        machine.succeed(f"{API} -o /tmp/whole http://localhost/api/v1/blobs/{blob} && cmp /tmp/track /tmp/whole")
        refused = machine.fail(f"{NAME} forget garage2 2>&1")
        assert "garage2 is still configured" in refused, refused
        machine.succeed("systemctl unset-environment BACKEND_BLOB_TARGET")
        restart()
        machine.wait_until_succeeds(f"{NAME} storage | grep -q 'by copies: 1 with 1'")

    with subtest("the credentials are the service's alone"):
        for backend in ["garage", "garage2"]:
            machine.fail(f"grep -q ${secret} /etc/credentials/demo/{backend}")
            machine.succeed(f"runuser -u {NAME} -- grep -q ${secret} /run/credentials/{NAME}.service/{backend}")
            for user in [CLIENT, "store-outsider"]:
                machine.fail(f"su - {user} -c 'cat /run/credentials/{NAME}.service/{backend}'")

    with subtest("the sweep deletes the objects no blob owns, and nothing else"):
        orphan = "demo/00000000-0000-4000-8000-000000000000/" + "0" * 64
        others = ["demo/readme.txt", "other/" + "0" * 64]
        for key in [orphan, *others]:
            machine.succeed(f"echo x | mc pipe s3/blobs/{key}")
        restart()
        machine.wait_until_succeeds(f"! mc ls --recursive s3/blobs | grep -q {orphan.split('/')[1]}")
        listed = objects()
        for key in others:
            assert key.split("/")[-1] in listed, listed
        assert blob in listed, listed

    with subtest("while S3 is down, uploads still work, reads fail fast, and the next pass catches up"):
        machine.systemctl("stop nginx.service")
        machine.succeed("head -c 50000 /dev/urandom > /tmp/second")
        second = upload("/tmp/second")
        assert status(second) == "200"
        assert status(blob) == "503", status(blob)
        machine.systemctl("start nginx.service")
        machine.wait_for_open_port(9000)
        assert second not in objects(), "it waited in the database"
        restart()
        machine.wait_until_succeeds(f"mc ls --recursive s3/blobs | grep -q {second}")
        machine.succeed(f"{API} -o /tmp/back http://localhost/api/v1/blobs/{second} && cmp /tmp/second /tmp/back")
        assert status(blob) == "200"

    with subtest("an object S3 lost reads as lost"):
        key = re.search(rf"demo/[0-9a-f-]+/{blob}", objects())
        assert key, objects()
        machine.succeed(f"mc rm s3/blobs/{key.group(0)}")
        assert status(blob) == "410", status(blob)

    with subtest("nothing of the credential file went in the log, failures included"):
        journal = machine.succeed(f"journalctl -u {NAME}.service --no-pager")
        assert "S3 is unavailable" in journal, "the outage was logged"
        for secret in ["${secret}", "${keyId}", "X-Amz", "localhost:9000"]:
            assert secret not in journal, f"{secret} in the journal"
  '';
}
