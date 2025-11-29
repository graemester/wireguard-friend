.PHONY: help test build up down clean logs status

help:
	@echo "WireGuard Friend - Integration Tests"
	@echo ""
	@echo "Commands:"
	@echo "  make test      - Run full integration test suite"
	@echo "  make build     - Build Docker containers"
	@echo "  make up        - Start containers (manual testing)"
	@echo "  make down      - Stop containers"
	@echo "  make clean     - Clean up containers and configs"
	@echo "  make logs      - Show container logs"
	@echo "  make status    - Show WireGuard status on all containers"

test:
	@echo "Running integration tests..."
	python3 test_connectivity.py

build:
	docker-compose build

up:
	docker-compose up -d
	@echo "Containers started. Use 'make status' to check WireGuard."

down:
	docker-compose down

clean:
	docker-compose down -v
	rm -rf configs/
	@echo "Cleaned up containers and configs"

logs:
	docker-compose logs -f

status:
	@echo "=== Coordination Server ==="
	@docker exec wgf-cs wg show 2>/dev/null || echo "WireGuard not running"
	@echo ""
	@echo "=== Subnet Router ==="
	@docker exec wgf-snr wg show 2>/dev/null || echo "WireGuard not running"
	@echo ""
	@echo "=== Remote-1 ==="
	@docker exec wgf-remote1 wg show 2>/dev/null || echo "WireGuard not running"
	@echo ""
	@echo "=== Remote-2 ==="
	@docker exec wgf-remote2 wg show 2>/dev/null || echo "WireGuard not running"
