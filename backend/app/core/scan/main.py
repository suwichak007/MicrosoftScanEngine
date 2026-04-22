from scanner.security_scanner import SecurityScanner


def main():
    scanner = SecurityScanner()
    score, results = scanner.run_baseline_scan()
    scanner.print_summary(score, results)


if __name__ == "__main__":
    main()
