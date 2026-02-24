{
  description = "TPM-backed PIN authentication PAM module";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0"; # stable Nixpkgs
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      ...
    }@inputs:

    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      mkPinpamPackage =
        pkgs:
        pkgs.rustPlatform.buildRustPackage {
          pname = "pinpam";
          version = "0.1.0";

          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = with pkgs; [
            pkg-config
            clang
            llvm
          ];

          buildInputs = with pkgs; [
            linux-pam
            tpm2-tss.dev
            openssl
            libclang.lib
          ];

          # Set environment variables for building
          OPENSSL_NO_VENDOR = 1;
          PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig:${pkgs.linux-pam}/lib/pkgconfig:${pkgs.tpm2-tss.dev}/lib/pkgconfig";

          buildPhase = ''
            runHook preBuild

            # Build the workspace
            cargo build --release --workspace

            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall

            # Install PAM module (shared library from pinpam-pam crate)
            mkdir -p $out/lib/security
            cp target/release/libpinpam.so $out/lib/security/
            cp target/release/libpinpam_master_key.so $out/lib/security/

            # Install pinutil binary
            mkdir -p $out/bin
            cp target/release/pinutil $out/bin/

            runHook postInstall
          '';
          phases = [
            "unpackPhase"
            "buildPhase"
            "installPhase"
          ];

          meta = with pkgs.lib; {
            description = "TPM-backed PIN authentication PAM module";
            license = licenses.mit;
            platforms = platforms.linux;
            maintainers = [ ];
          };
        };
      forEachSupportedSystem =
        f:
        nixpkgs.lib.genAttrs supportedSystems (
          system:
          f {
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ rust-overlay.overlays.default ];
            };
          }
        );
    in
    {
      packages = forEachSupportedSystem (
        { pkgs }:
        {
          default = mkPinpamPackage pkgs;
        }
      );

      nixosModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          cfg = config.security.pinpam;

          # Bind individual leaves to avoid forcing evaluation of the whole security.pinpam subtree
          pinpamEnable = cfg.enable;
          pinpamPkg = cfg.package;
          enableTpmAccess = cfg.enableTpmAccess;
          enableSudoPin = cfg.enableSudoPin;
          enableLoginPin = cfg.enableLoginPin;
          enableKdePin = cfg.enableKdePin;
          enableSystemAuthPin = cfg.enableSystemAuthPin;
          enableHyprlockPin = cfg.enableHyprlockPin;
          enablePolkitPin = cfg.enablePolkitPin;
          pinutilPath = cfg.pinutilPath;
          policyFile = cfg.policyFile;
          pinPolicyMinLength = cfg.pinPolicy.minLength;
          pinPolicyMaxLength = cfg.pinPolicy.maxLength;
          pinPolicyMaxAttempts = cfg.pinPolicy.maxAttempts;
          enableMasterKeySubstitution = cfg.enableMasterKeySubstitution;
        in
        {
          options.security.pinpam = {
            enable = lib.mkEnableOption "TPM-backed PIN authentication PAM module";

            package = lib.mkOption {
              type = lib.types.package;
              default = mkPinpamPackage pkgs;
              description = "The pinpam package to use";
            };

            enableTpmAccess = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = ''
                Add udev rules to allow the tss group read/write access to TPM devices.
                This is required for non-root users to use the TPM for PIN operations.
              '';
            };

            enableSudoPin = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Enable TPM PIN authentication for sudo.
                This adds the pinpam module to sudo's PAM configuration with priority 10 lower
                than standard unix authentication (order = config.security.pam.services.sudo.rules.auth.unix.order + 10).
                Users can authenticate with either their standard password or TPM PIN.
              '';
            };
            enableSystemAuthPin = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Enable TPM PIN authentication for the system-auth PAM service.
                This adds the pinpam module as a sufficient authentication method so users can
                log in with either their regular password or TPM PIN depending on the service
                stack consuming system-auth.
              '';
            };

            enableLoginPin = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Enable TPM PIN authentication for the login PAM service.
                This adds the pinpam module as a sufficient authentication method so login
                users can authenticate with either their standard password or TPM PIN.
              '';
            };
            enableKdePin = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Enable TPM PIN authentication for the kde service.
                This adds the pinpam module as a sufficient authentication method so login
                users can authenticate with either their standard password or TPM PIN.
              '';
            };
            enableHyprlockPin = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Enable TPM PIN authentication for the hyprlock PAM service.
                Users can authenticate with either their standard password or TPM PIN.
              '';
            };

            enablePolkitPin = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Enable TPM PIN authentication for polkit-1.
                This also adjusts the polkit-agent-helper@.service to allow TPM device access.
                Users can authenticate with either their standard password or TPM PIN.
              '';
            };

            pinutilPath = lib.mkOption {
              type = lib.types.str;
              default = "/run/wrappers/bin/pinutil";
              defaultText = lib.literalExpression ''"\${config.security.wrapperDir}/pinutil"'';
              description = ''
                Absolute path to the trusted pinutil binary. This value is embedded into the
                generated PIN policy to ensure pinpam only invokes the expected executable.
              '';
            };

            pinPolicy = {
              minLength = lib.mkOption {
                type = lib.types.ints.unsigned;
                default = 4;
                description = ''
                  Minimum PIN length enforced by the TPM policy.
                  Values below 4 are strongly discouraged because they significantly weaken the brute-force resistance of the PIN.
                '';
              };

              maxLength = lib.mkOption {
                type = lib.types.nullOr lib.types.ints.unsigned;
                default = 8;
                description = ''
                  Maximum PIN length enforced by the TPM policy.
                  Set to null to disable the upper bound.
                '';
              };

              maxAttempts = lib.mkOption {
                type = lib.types.ints.unsigned;
                default = 5;
                description = ''
                  Maximum number of failed PIN attempts before user lockout.
                  Set to 0 to disable lockout entirely.
                  This configures per-user PIN counters using TPM_NT_PIN_FAIL hardware-backed protection.
                '';
              };
            };

            policyFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              description = ''
                Path to a custom PIN counter policy configuration file.
                If set, this file will be used instead of the auto-generated one from pinPolicy options.
                The file must contain whitespace-separated key/value pairs understood by pinpam, such as:
                pin_min_length=4 pin_max_length=8 pin_lockout_max_attempts=5
              '';
            };

            substituteMasterKeyAuth = lib.mkOption {
              type = lib.types.attrsOf (
                lib.types.submodule (
                  { name, ... }:
                  {
                    options.enable = lib.mkEnableOption (
                      "Insert pinpam master-key module into the '${name}' PAM service auth stack"
                    );
                    options.rewriteSufficientRules = lib.mkOption {
                      type = lib.types.listOf lib.types.str;
                      default = [ "unix" ];
                      description = ''
                        List of auth rule names whose control should be rewritten from "sufficient"
                        to "[success=1 default=ignore]" so that after success they skip the deny
                        rule and reach the master-key module.
                      '';
                    };
                    options.denyOrder = lib.mkOption {
                      type = lib.types.int;
                      default = 13000;
                      description = "Order for the pam_deny.so rule inserted before master-key (after rewritten sufficient rules).";
                    };
                    options.masterKeyOrder = lib.mkOption {
                      type = lib.types.int;
                      default = 13010;
                      description = "Order for the libpinpam_master_key.so rule.";
                    };
                  }
                )
              );
              default = { };
              description = ''
                Per-PAM-service toggles to append the pinpam master-key module to the bottom
                of the auth stack.

                For each enabled service, this module inserts rules at the configured order:

                auth requisite pam_deny.so           (order = denyOrder)
                auth optional  libpinpam_master_key.so (order = masterKeyOrder)

                Rules listed in rewriteSufficientRules have their control changed to
                "[success=1 default=ignore]" so successful auth skips the deny rule.

                NOTE: You must also set enableMasterKeySubstitution = true for this to take effect.
              '';
            };

            enableMasterKeySubstitution = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Master switch to enable master-key PAM substitution.
                Set this to true and configure substituteMasterKeyAuth for the desired services.
              '';
            };
          };

          config = lib.mkIf pinpamEnable (
            lib.mkMerge [
              {
                # Add the PAM module to the system
                environment.systemPackages = [ pinpamPkg ];

                # Set up security wrapper for pinutil with setgid
                security.wrappers.pinutil = {
                  setgid = true;
                  owner = "root";
                  group = "tss";
                  source = "${pinpamPkg}/bin/pinutil";
                };

                # Ensure tss group exists
                users.groups.tss = { };

                # Install policy file
                environment.etc."pinpam/policy" =
                  if policyFile != null then
                    {
                      # Use custom policy file
                      source = policyFile;
                      mode = "0644";
                      user = "root";
                      group = "root";
                    }
                  else
                    {
                      # Generate policy file from pinPolicy options
                      text =
                        let
                          policyLines = [
                            "pin_min_length=${toString pinPolicyMinLength}"
                          ]
                          ++ lib.optional (
                            pinPolicyMaxLength != null
                          ) "pin_max_length=${toString pinPolicyMaxLength}"
                          ++ [
                            "pin_lockout_max_attempts=${toString pinPolicyMaxAttempts}"
                            "pinutil_path=${toString pinutilPath}"
                          ];
                        in
                        lib.concatStringsSep "\n" (policyLines ++ [ "" ]);
                      mode = "0644";
                      user = "root";
                      group = "root";
                    };
              }

              # TPM access configuration
              (lib.mkIf enableTpmAccess {
                # Enable udev service
                services.udev.enable = true;

                # Add udev rules for TPM access by tss group
                services.udev.extraRules = ''
                  # TPM device access for tss group
                  KERNEL=="tpm[0-9]*", TAG+="systemd", MODE="0660", GROUP="tss"
                  KERNEL=="tpmrm[0-9]*", TAG+="systemd", MODE="0660", GROUP="tss"
                '';
              })

              # Sudo PAM configuration
              (lib.mkIf enableSudoPin {
                security.pam.services.sudo.rules.auth.pinpam = {
                  control = "sufficient";
                  modulePath = "${pinpamPkg}/lib/security/libpinpam.so";
                  order = 11050;  # Default unix order is 11100, place before it
                };
              })

              # Login PAM configuration
              (lib.mkIf enableLoginPin {
                security.pam.services.login.rules.auth.pinpam = {
                  control = "sufficient";
                  modulePath = "${pinpamPkg}/lib/security/libpinpam.so";
                  order = 11050;
                };
              })
              # KDE PAM configuration
              (lib.mkIf enableKdePin {
                security.pam.services.kde.rules.auth.pinpam = {
                  control = "sufficient";
                  modulePath = "${pinpamPkg}/lib/security/libpinpam.so";
                  order = 11050;
                };
              })
              (lib.mkIf enableSystemAuthPin {
                security.pam.services."system-auth".rules.auth.pinpam = {
                  control = "sufficient";
                  modulePath = "${pinpamPkg}/lib/security/libpinpam.so";
                  order = 11050;
                };
              })

              (lib.mkIf enableHyprlockPin {
                security.pam.services.hyprlock.rules.auth.pinpam = {
                  control = "sufficient";
                  order = 11050;
                  modulePath = "${pinpamPkg}/lib/security/libpinpam.so";
                };
              })

              (lib.mkIf enablePolkitPin {
                security.pam.services.polkit-1.rules.auth.pinpam = {
                  control = "sufficient";
                  order = 11050;
                  modulePath = "${pinpamPkg}/lib/security/libpinpam.so";
                };
              })

              (lib.mkIf enablePolkitPin {
                systemd.services."polkit-agent-helper@".serviceConfig = {
                  PrivateDevices = "no";
                  DeviceAllow = [
                    "/dev/tpmrm0 rw"
                    "/dev/ptmx rw"
                  ];
                };
              })

              # Append master-key auth module to selected PAM services
              (lib.mkIf enableMasterKeySubstitution {
                security.pam.services =
                  let
                    enabledServices = lib.filterAttrs (
                      _service: serviceCfg:
                      (serviceCfg.enable or false)
                    ) cfg.substituteMasterKeyAuth;

                    mkService = service: serviceCfg:
                      let
                        denyRuleName = "pinpamMasterKeyDeny";
                        masterKeyRuleName = "pinpamMasterKey";

                        # Rewrite specified rules to use skip-on-success control
                        sufficientControlOverrides =
                          lib.genAttrs serviceCfg.rewriteSufficientRules (_ruleName: {
                            control = lib.mkForce "[success=1 default=ignore]";
                          });
                      in
                      {
                        rules.auth =
                          sufficientControlOverrides
                          // {
                            "${denyRuleName}" = {
                              control = "requisite";
                              modulePath = "pam_deny.so";
                              order = serviceCfg.denyOrder;
                            };

                            "${masterKeyRuleName}" = {
                              control = "optional";
                              modulePath = "${pinpamPkg}/lib/security/libpinpam_master_key.so";
                              order = serviceCfg.masterKeyOrder;
                            };
                          };
                      };
                  in
                  lib.mapAttrs mkService enabledServices;
              })
            ]
          );
        };

      devShells = forEachSupportedSystem (
        { pkgs }:
        {
          default = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
              pkg-config
              rust-bin.stable.latest.default
              clang
              llvm
            ];

            packages =
              with pkgs;
              [
                # Rust development tools
                rust-analyzer
                cargo-audit
                cargo-deny
                cargo-watch

                # System dependencies
                linux-pam
                tpm2-tss.dev
                openssl.dev
                tpm2-tools
                libclang.lib

                # C/C++ development tools
                clang-tools

                # Testing and debugging
                libpam-wrapper
                pamtester
                valgrind
                strace

                # Documentation and linting
                codespell
              ]
              ++ (if system == "aarch64-darwin" then [ ] else [ gdb ]);

            shellHook = ''
              # Set up environment for Rust development
              export RUST_SRC_PATH="${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}"
              export RUST_BACKTRACE=1

              # PKG-CONFIG setup for native dependencies  
              export PKG_CONFIG_PATH="${pkgs.openssl.dev}/lib/pkgconfig:${pkgs.linux-pam}/lib/pkgconfig:${pkgs.tpm2-tss.dev}/lib/pkgconfig"
              export OPENSSL_NO_VENDOR=1

              # Clang setup for bindgen and native builds
              export LIBCLANG_PATH="${pkgs.libclang.lib}/lib"
              export BINDGEN_EXTRA_CLANG_ARGS="-I${pkgs.clang}/resource-root/include"

              # PAM testing environment
              export PAM_WRAPPER=1
              export PAM_WRAPPER_SERVICE_DIR=.
              export LD_PRELOAD=${pkgs.libpam-wrapper}/lib/libpam_wrapper.so

              echo "🦀 Rust TPM PIN PAM development environment loaded!"
              echo "📦 Available tools: cargo, rust-analyzer, clippy, rustfmt"
              echo "🔧 System deps: PAM, TPM2-TSS, OpenSSL"
              echo "🧪 Testing: libpam-wrapper, pamtester available"
            '';
          };
        }
      );
    };
}
