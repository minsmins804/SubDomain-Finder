import asyncio
from subdomainfinder.services import ServiceScanner

async def main():
    domain = "example.com"  # đổi thành domain bạn muốn test
    scanner = ServiceScanner(domain)
    result = await scanner.scan()
    print(f"✅ Tổng cộng {len(result)} subdomain tìm được:")
    for s in sorted(result):
        print(s)

if __name__ == "__main__":
    asyncio.run(main())
