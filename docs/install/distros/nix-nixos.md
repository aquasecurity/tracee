# Nix/NixOS (Community)

If installing `tracee` via `nix` please ensure you're running a kernel with libbpf CO-RE support, see Tracee's [prerequisites](./../install/prerequisites.md) for more info

Direct issues installing `tracee` via `nix` through the channels mentioned [here](https://nixos.wiki/wiki/Support) (**non-CO-RE not supported**)

`nix-env --install -A nixpkgs.tracee`

Or through your configuration as usual

NixOS:

```nix
  # your other config ...
  environment.systemPackages = with pkgs; [
    # your other packages ...
    tracee
  ];
```

home-manager:

```nix
  # your other config ...
  home.packages = with pkgs; [
    # your other packages ...
    tracee
  ];
```

