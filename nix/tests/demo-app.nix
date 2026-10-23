# The stand-in app of the VM tests: the backend only needs something to serve.
pkgs: pkgs.writeTextDir "index.html" "<!doctype html><title>e2ee-store demo</title>\n"
