import argparse
from zte_toolkit import H168NClient, H168NDiagnostics


def main():
    parser = argparse.ArgumentParser(description="ZTE ZXHN H168N V3.1 Toolkit CLI")
    parser.add_argument("action", choices=["detect", "info", "set-wifi"], help="Action to run")
    parser.add_argument("--bind-ip", default=None)
    parser.add_argument("--target", default="192.168.1.1")
    parser.add_argument("--ssid", default="")
    parser.add_argument("--password", default="")
    args = parser.parse_args()

    client = H168NClient(bind_ip=args.bind_ip, target_ip=args.target)
    diag = H168NDiagnostics(client)

    if args.action == "detect":
        res = diag.detect_adapters()
        print(res["raw"])
    elif args.action == "info":
        res = diag.get_info()
        print(res["raw"])
    elif args.action == "set-wifi":
        ok, out, err = client.set_wifi(args.ssid, args.password)
        print(out or err)


if __name__ == "__main__":
    main()
