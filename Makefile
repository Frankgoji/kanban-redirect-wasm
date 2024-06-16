all: build-wasm build-react

clean: clean-wasm clean-react

clean-wasm:
	rm -r pkg || true

clean-react:
	rm -r react/build || true

build-wasm:
	wasm-pack build
	cp pkg/tumblr_kanban_rust*.js pkg/tumblr_kanban_rust*.wasm react/app/

build-react:
	cd react && npm run build

build-react-debug:
	cd react && npm run debug_build
