.PHONY: lab lab-full lab-down lab-logs test test-unit test-integration

lab:  ## Build and start the FRR integration lab
	docker compose -f lab/docker-compose.yml up -d --build
	@echo "Waiting for SSH on r1/r2..."
	@for i in $$(seq 1 30); do \
		nc -z localhost 2211 2>/dev/null && nc -z localhost 2212 2>/dev/null && echo "lab up: r1=localhost:2211 r2=localhost:2212 (netnerd/netnerd123)" && exit 0; \
		sleep 1; \
	done; \
	echo "SSH did not come up in 30s — check 'make lab-logs'"; exit 1

lab-full:  ## Start the lab plus the NETCONF node (builds netopeer2 from source)
	docker compose -f lab/docker-compose.yml --profile full up -d --build
	@echo "Waiting for SSH on r1/r2 NETCONF on netconf1 and gNMI on gnmi1..."
	@for i in $$(seq 1 90); do \
		nc -z localhost 2211 2>/dev/null && nc -z localhost 2212 2>/dev/null \
			&& nc -z localhost 2230 2>/dev/null && nc -z localhost 57400 2>/dev/null \
			&& echo "lab up: r1=2211 r2=2212 netconf1=2230 gnmi1=57400 (netnerd/netnerd123)" && exit 0; \
		sleep 1; \
	done; \
	echo "lab did not come up in 90s — check 'make lab-logs'"; exit 1

lab-down:  ## Tear down the lab
	docker compose -f lab/docker-compose.yml --profile full down -v

lab-logs:
	docker compose -f lab/docker-compose.yml --profile full logs --tail=50

test-unit:  ## Fast tests, no lab required
	python -m pytest tests/unit -v

test-integration:  ## Requires `make lab`
	python -m pytest tests/integration -v

test: test-unit test-integration
