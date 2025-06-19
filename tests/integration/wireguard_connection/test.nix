ctx: ctx.scoped rec {
  # File imports ############################

  inherit (ctx) scoped;

  inherit (builtins) readFile toString toJSON;

  inherit (ctx.flake.inputs) nixpkgs;
  esc = nixpkgs.lib.strings.escapeShellArg;

  inherit (ctx.system) pkgs packages;

  # Configuration Variables #################

  config.qkdSimulator.port = 1001;
  config.qkdSimulator.host = "ada";
  config.wireguard.interface = "daisyway0";
  config.wireguard.port = 1002;
  config.daisyway.port = 1003;
  config.peers.ada.ip = "192.168.1.1";
  config.peers.bob.ip = "192.168.1.2";
  config.peers.ada.wg.sk = "+NOZyoj5dyFai+TdC/vvYB+tfRPrZMjTgf3smrLQFFs=";
  config.peers.ada.wg.pk = "sNECL2dLH98B43cYtXc6jAhRb5ioNqqwWBNmLqoj1y0=";
  config.peers.bob.wg.sk = "QEpVos8mjb4b/z0EUpKUlLEIWmJmtYx3flCHklFttko=";
  config.peers.bob.wg.pk = "UyImgoxw9JDZC+lqq4D/MJvdrnxhpdCPX5bNsiizdVc=";

  # Test configuration entrypoint ###########

  result.name = "daisyway-wireguard-connection";

  # The host configuration variables are built below by merging common configuration
  # variables with host-specific ones
  result.nodes.ada = { ... }: configureHost ada;
  result.nodes.bob = { ... }: configureHost bob;

  # The test script is in an extra file to avoid bloat in this one. To give it access
  # to the configuration variables in this file, we serialize the config variables above
  # as JSON and have the python script decode that JSON string.
  result.testScript = ''
    configJson = '${toJSON config}'
    ${readFile ./test.py}
  '';

  # Per-host configuration ##################

  # A generic solution to merge these configuration variables is quite hard, because
  # we would need to annotate whether attribute sets are supposed to be merged recursively
  # or whether they are supposed to be overwritten.
  #
  # To avoid this extra complexity, we just manually merge the variables here.
  #
  # Producing the TOML file adds extra complexity; which is another reason we chose the explicit approach.
  configureHost = (hostConfig: scoped rec {
    dw_comm = common.daisywayConfig;
    dw_host = hostConfig.daisywayConfig or {};
    auto.etc."daisyway/baseline.toml".source = toml "daisyway-config" {
      etsi014 = dw_comm.etsi014 // (dw_host.etsi014 or {});
      peer = dw_comm.peer // (dw_host.peer or {});
      wireguard = dw_comm.wireguard // (dw_host.wireguard or {});
    };

    result.systemd.services = common.services // (hostConfig.services or {});
    result.environment.etc = auto.etc // common.etc // (hostConfig.etc or {});
    result.environment.systemPackages = common.systemPackages ++ (hostConfig.systemPackages or []);

    result.networking.firewall.allowedTCPPorts = common.tcpPorts ++ (hostConfig.tcpPorts or []);
    result.networking.firewall.allowedUDPPorts = common.udpPorts ++ (hostConfig.udpPorts or []);
  });

  # System packages to be installed on both hosts.
  # This is primarily daisyway itself and some tools for debugging
  common.systemPackages = []
    ++ (with packages; [
      daisyway
    ])
    ++ (with pkgs; [
      wireguard-tools
      iproute2
      nmap
    ]);

  # Ada also hosts the QKD simulator
  ada.systemPackages = []
    ++ (with packages; [
      daisywayQkdSimulator
    ]);

  common.tcpPorts = [ config.qkdSimulator.port config.daisyway.port ];
  common.udpPorts = [ config.wireguard.port ];

  # Ability to start the QKD simulator
  ada.services.daisywayQkdSimulator = {
    requires = [ "network-online.target" ];
    serviceConfig.ExecStart = "${esc packages.daisywayQkdSimulator}/bin/simulator --addr [::]:${esc config.qkdSimulator.port}";
  };

  # Ability to start daisyway itself
  common.services.daisyway = {
    requires = [ "network-online.target" ];
    serviceConfig.ExecStart = "${esc packages.daisyway}/bin/daisyway exchange --config /etc/daisyway/baseline.toml";
    environment.RUST_LOG = "debug";
    environment.RUST_BACKTRACE = "1";
  };

  # Daisyway configuration file
  common.daisywayConfig = {
    peer = {};

    etsi014.url = "http://${config.qkdSimulator.host}:${toString config.qkdSimulator.port}";
    # TODO: Is this parameter required?
    etsi014.remote_sae_id = "SAE_002";

    wireguard.interface = config.wireguard.interface;
  };
  ada.daisywayConfig = {
    # Should support host names
    peer.listen = "[::]:${toString config.daisyway.port}";
    wireguard.self_public_key = config.peers.ada.wg.pk;
    wireguard.peer_public_key = config.peers.bob.wg.pk;
  };
  bob.daisywayConfig = {
    peer.endpoint = "ada:${toString config.daisyway.port}";
    wireguard.self_public_key = config.peers.bob.wg.pk;
    wireguard.peer_public_key = config.peers.ada.wg.pk;
  };

  # Each host gets access to its own secret key
  ada.etc."daisyway/ada.wg.sk".text = config.peers.ada.wg.sk;
  bob.etc."daisyway/bob.wg.sk".text = config.peers.bob.wg.sk;

  # Hosts get mutual access to each others public key
  common.etc."daisyway/ada.wg.pk".text = config.peers.ada.wg.pk;
  common.etc."daisyway/bob.wg.pk".text = config.peers.bob.wg.pk;

  # Utility functions #######################

  toml = (data: scoped rec {
    formatter = pkgs.formats.toml {};
    result = formatter.generate data;
  });
}
