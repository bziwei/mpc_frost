.PHONY: all clean

all: build

EXECUTABLES = mpc_sesman demo_keygen demo_sign
build: kill_tmux
	cargo build
	mkdir out || true
	for exe in $(EXECUTABLES); do \
		cp target/debug/$$exe out/$$exe; \
	done

demo_keygen: build
	@tmux new-session -s frost \
		-n man -d ";" new-window \
		-n p1  -d ";" new-window \
		-n p2  -d ";" new-window \
		-n p3  -d ";" new-window \
		-n p4  -d ";" new-window \
		-n p5  -d ";"
	@sleep 1
	@tmux send-keys -t frost:man "cd $(shell pwd)/out && ./mpc_sesman" C-m
	@sleep 1
	@tmux send-keys -t frost:p1  "cd $(shell pwd)/out && ./demo_keygen -m 1" C-m
	@tmux send-keys -t frost:p2  "cd $(shell pwd)/out && ./demo_keygen -m 2" C-m
	@tmux send-keys -t frost:p3  "cd $(shell pwd)/out && ./demo_keygen -m 3" C-m
	@tmux send-keys -t frost:p4  "cd $(shell pwd)/out && ./demo_keygen -m 4" C-m
	@tmux send-keys -t frost:p5  "cd $(shell pwd)/out && ./demo_keygen -m 5" C-m

demo_sign: build
	@tmux new-session -s frost \
		-n p1  -d ";" new-window \
		-n p2  -d ";" new-window \
		-n p3  -d ";" new-window \
		-n p4  -d ";" new-window \
		-n p5  -d ";"
		-n man -d ";" new-window \
	@sleep 1
	@tmux send-keys -t frost:man "cd $(shell pwd)/out && ./mpc_sesman" C-m
	@sleep 1
	@tmux send-keys -t frost:p1  "cd $(shell pwd)/out && ./demo_sign -s 1 -n 3 -m 1" C-m
	@tmux send-keys -t frost:p3  "cd $(shell pwd)/out && ./demo_sign -s 2 -n 3 -m 3" C-m
	@tmux send-keys -t frost:p5  "cd $(shell pwd)/out && ./demo_sign -s 3 -n 3 -m 5" C-m

clean: kill_tmux
	cargo clean
	rm -r out

kill_tmux:
	tmux kill-session -t frost || true
