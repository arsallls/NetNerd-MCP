.PHONY: lab lab-down lab-logs test test-unit test-integration

lab:  ## Build and start the FRR integration lab
	docker compose -f lab/docker-compose.yml up -d --build
	@echo "Waiting for SSH on r1/r2..."
	@for i in $$(seq 1 30); do \
		nc -z localhost 2211 2>/dev/null && nc -z localhost 2212 2>/dev/null && echo "lab up: r1=localhost:2211 r2=localhost:2212 (netnerd/netnerd123)" && exit 0; \
		sleep 1; \
	done; \
	echo "SSH did not come up in 30s — check 'make lab-logs'"; exit 1

lab-down:  ## Tear down the lab
	docker compose -f lab/docker-compose.yml down -v

lab-logs:
	docker compose -f lab/docker-compose.yml logs --tail=50

test-unit:  ## Fast tests, no lab required
	python -m pytest tests/unit -v

test-integration:  ## Requires `make lab`
	python -m pytest tests/integration -v

test: test-unit test-integration
