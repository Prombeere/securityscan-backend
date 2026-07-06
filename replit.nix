{ pkgs }: {
  deps = [
    pkgs.python312
    pkgs.python312Packages.pip
    pkgs.go_1_21
    pkgs.git
    pkgs.gnumake
  ];
}