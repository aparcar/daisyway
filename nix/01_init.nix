outer_ctx: outer_ctx.scoped rec {
  inherit (builtins) trace;

  ctx = outer_ctx // { inherit config; };

  inherit (ctx) scoped;

  inherit (ctx.flake.inputs) nixpkgs flake-utils;
  inherit (nixpkgs.lib) genAttrs zipAttrsWith;
  inherit (nixpkgs.lib.debug) traceVal;
  inherit (flake-utils.lib) allSystems eachSystem;

  result = {
    devShells = eachSupportedSystem (system: (setupSystem system).devShells);
    packages = eachSupportedSystem (system: (setupSystem system).packages);
    apps = eachSupportedSystem (system: (setupSystem system).apps);
    checks = eachSupportedSystem (system: (setupSystem system).checks);
  };

  setupSystem = (system_name: scoped rec {
    result = (import ./02_main.nix) (ctx // {
      system.name = system_name;
    });
  });

  config = {
    supportedSystems = allSystems;
    poetry.projectDir = ctx.flake.self;
  };

  eachSupportedSystem = genAttrs config.supportedSystems;
}
