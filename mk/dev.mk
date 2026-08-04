#
# Editor attachment surface (host-side; included by mk/dispatch.mk).
#
# Two tiers, adopted from the miski build system:
#
#   lsp-*  - a language server from the buildenv image over stdio: the floor.
#            Works for any editor that can spawn a subprocess; no daemon,
#            keys, or ports. The repo is mounted AT ITS HOST PATH, so the
#            file:// URIs the server emits match what the editor sees - no
#            path translation - and diagnostics come from the exact
#            toolchain 'make' builds with.
#   dev    - a persistent box for attaching a full editor (engine-native:
#            TRAMP's podman method, VS Code/Cursor attach, plain exec; an
#            sshd on loopback is the optional extra for Remote-SSH-only
#            editors). Your editor, config and clipboard stay on the host;
#            only the session runs inside.
#

# fail fast with a hint instead of triggering a rebuild mid-editing-session:
# the lsp/dev targets deliberately do not depend on image freshness
define need_image
$(CONTAINER_ENGINE) image inspect $(BUILDENV_IMAGE) > /dev/null 2>&1 || { \
	echo "make: $(BUILDENV_IMAGE) not built yet - run 'make image' first" >&2; \
	exit 1; \
}
endef

#
# language servers over stdio
#

# mirrors the unprivileged run profile, but mounts the repo at its host path;
# rootful docker needs the uid mapped so index/cache writes are not root's
LSP_RUN = $(CONTAINER_ENGINE) run -i --rm \
	$(if $(SELINUX_ENFORCING),--security-opt label=disable) \
	$(if $(ENGINE_ROOTLESS),--user root,--user $(UID):$(GID)) \
	-e TRACEE_BUILDENV=1 \
	-v "$(CURDIR):$(CURDIR)" \
	-w "$(CURDIR)" \
	$(BUILDENV_IMAGE)

.PHONY: lsp-go
lsp-go: ## gopls over stdio (point your editor's server command here)
	@$(call need_image)
	@exec $(LSP_RUN) gopls

.PHONY: lsp-c
lsp-c: ## clangd over stdio (point your editor's server command here)
	@$(call need_image)
	@exec $(LSP_RUN) clangd

# for editors that must wrap the command rather than exec a make target
.PHONY: lsp-print-go
lsp-print-go:
	@echo $(LSP_RUN) gopls

.PHONY: lsp-print-c
lsp-print-c:
	@echo $(LSP_RUN) clangd

#
# persistent dev box
#

SSH_PORT ?= 2222
DEV_BOX ?= tracee-dev-box
# a named volume for the box's home: caches (go, gopls, clangd) survive box
# recreation without landing in the repo; clean-dev removes it
DEV_HOME_VOL ?= tracee-dev-home
# a self-contained keypair (gitignored), generated on first 'make dev'; set
# SSH_PUBKEY to use a key of your own instead
DEV_KEY ?= $(CURDIR)/.devssh/id_ed25519
SSH_PUBKEY ?=
# a persistent host key so the box keeps one ssh fingerprint across restarts
DEV_HOSTKEY ?= $(CURDIR)/.devssh/ssh_host_ed25519_key

define attach_menu
echo ">> Attach your editor to $(DEV_BOX) (start it with 'make dev'):"; \
echo "     Emacs (TRAMP):     /podman:$(DEV_BOX):/tracee/"; \
echo "     VS Code / Cursor:  Dev Containers: Attach to Running Container -> $(DEV_BOX)"; \
echo "     Shell / any tool:  $(CONTAINER_ENGINE) exec -it $(DEV_BOX) bash"; \
echo "   Optional, over ssh (for editors that speak only Remote-SSH):"; \
echo "     make dev-ssh"; \
echo "     raw: ssh -i $(DEV_KEY) -o HostKeyAlias=$(DEV_BOX) -p $(SSH_PORT) tracee@localhost"
endef

.PHONY: dev
dev: ## start the persistent dev box for your editor (see make attach)
	@$(call need_image)
	@if [ -n "$$($(CONTAINER_ENGINE) ps -q -f name=$(DEV_BOX))" ]; then \
		echo ">> $(DEV_BOX) is already running; leaving it as is (dev-stop to recreate)."; \
		$(call attach_menu); \
		exit 0; \
	fi; \
	key="$(SSH_PUBKEY)"; \
	if [ -z "$${key}" ]; then \
		key="$(DEV_KEY).pub"; \
		if [ ! -f "$(DEV_KEY)" ]; then \
			mkdir -p "$$(dirname "$(DEV_KEY)")"; \
			ssh-keygen -t ed25519 -f "$(DEV_KEY)" -N "" -q -C tracee-dev; \
			echo ">> generated a dev key at $(DEV_KEY)"; \
		fi; \
	fi; \
	if [ ! -f "$(DEV_HOSTKEY)" ]; then \
		mkdir -p "$$(dirname "$(DEV_HOSTKEY)")"; \
		ssh-keygen -t ed25519 -f "$(DEV_HOSTKEY)" -N "" -q -C tracee-dev-host; \
	fi; \
	$(CONTAINER_ENGINE) rm -f $(DEV_BOX) > /dev/null 2>&1 || true; \
	$(CONTAINER_ENGINE) run -d --name $(DEV_BOX) --hostname $(DEV_BOX) \
		$(if $(SELINUX_ENFORCING),--security-opt label=disable) \
		$(if $(ENGINE_ROOTLESS),--userns=keep-id,--user root) \
		-e SSH_PORT=$(SSH_PORT) \
		-p 127.0.0.1:$(SSH_PORT):$(SSH_PORT) \
		-v "$(CURDIR)":/tracee \
		-v $(DEV_HOME_VOL):/home/tracee \
		-v "$${key}":/run/tracee/authorized_keys:ro \
		-v "$(DEV_HOSTKEY)":/run/tracee/hostkey:ro \
		$(BUILDENV_IMAGE) tracee-sshd; \
	$(call attach_menu)

.PHONY: dev-stop
dev-stop: ## stop and remove the dev box
	-$(CONTAINER_ENGINE) rm -f $(DEV_BOX)

.PHONY: attach
attach: ## print how to attach your editor to the running box
	@$(call attach_menu)

# HostKeyAlias records the box under its own name (not [localhost]:2222) in a
# project-local known_hosts, prompt-free and out of your global file
.PHONY: dev-ssh
dev-ssh: ## ssh into the running dev box
	@exec ssh -i $(DEV_KEY) -p $(SSH_PORT) \
		-o HostKeyAlias=$(DEV_BOX) \
		-o UserKnownHostsFile=$(CURDIR)/.devssh/known_hosts \
		-o StrictHostKeyChecking=accept-new \
		tracee@localhost

.PHONY: clean-dev
clean-dev: dev-stop ## remove the dev box and its home volume (caches rebuild)
	-$(CONTAINER_ENGINE) volume rm $(DEV_HOME_VOL) 2> /dev/null
	rm -rf $(CURDIR)/.devssh
