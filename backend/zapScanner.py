import os
import time
import uuid
from zapv2 import ZAPv2

def scan(target_url, zap_api_key=None, zap_host='127.0.0.1', zap_port=8090, wait=True):
    target_url = target_url.rstrip('/') + '/'
    zap_api_key = zap_api_key or os.getenv('ZAP_API_KEY')
    if not zap_api_key:
        return ["ZAP API Key is not configured. Set ZAP_API_KEY or pass zap_api_key param."]

    proxies = {'http': f'http://{zap_host}:{zap_port}', 'https': f'http://{zap_host}:{zap_port}'}
    zap = ZAPv2(apikey=zap_api_key, proxies=proxies)

    findings = []
    context_name = f"context_{uuid.uuid4().hex[:8]}"

    try:
        # connectivity check
        try:
            version = zap.core.version
            print(f"Connected to ZAP (version {version}) at {zap_host}:{zap_port}")
        except Exception as ex:
            raise RuntimeError(f"Cannot reach ZAP API: {ex}")

        # create session
        zap.core.new_session(name=f"session_{context_name}", overwrite=True)
        print("New session created.")

        zap.context.new_context(context_name)
        contexts = zap.context.context_list  # returns comma-separated names
        if context_name not in contexts:
            print("Context creation reported, but context not in list; continuing anyway.")
        ctx_info = zap.context.context(context_name)
        context_id = None
        try:
            context_id = int(ctx_info.get('id'))
        except Exception:
            context_id = None

        print(f"Context '{context_name}' created (id={context_id}).")

        print(f"Opening target URL in ZAP: {target_url}")
        zap.urlopen(target_url)
        time.sleep(2)  # short pause for ZAP to register the URL

        # Spider
        print("Starting spider...")
        spider_id = zap.spider.scan(target_url)
        if not spider_id:
            print("Spider returned no id; continuing but spider may not have run.")
        else:
            while int(zap.spider.status(spider_id)) < 100:
                print(f"Spider progress: {zap.spider.status(spider_id)}%")
                time.sleep(3)
            print("Spider finished.")

        try:
            while int(zap.pscan.records_to_scan) > 0:
                print(f"Passive records remaining: {zap.pscan.records_to_scan}")
                time.sleep(2)
        except Exception:
            pass

        # Active scan
        print("Starting active scan (this will touch many pages)...")
        ascan_id = zap.ascan.scan(target_url, recurse=True, inscopeonly=False)
        if not ascan_id:
            print("ascan.scan() returned no id. It may still run; monitor progress via zap.ascan.status().")
        else:
            while int(zap.ascan.status(ascan_id)) < 100:
                print(f"Active scan progress: {zap.ascan.status(ascan_id)}% | Alerts so far: {len(zap.core.alerts())}")
                time.sleep(10)
            print("Active scan finished.")


        # Gather alerts
        alerts = zap.core.alerts(baseurl=target_url, count=1637)
        print(f"Total alerts found: {len(alerts)}")
        for a in alerts:
            findings.append(f"[{a.get('risk')}] {a.get('name')} - {a.get('url')}")

    except Exception as e:
        msg = f"ZAP scan failed: {e}"
        print(msg)
        findings.append(msg)
    finally:
        try:
            zap.context.remove_context(context_name)
            print("Context removed.")
        except Exception as e:
            print(f"Failed to remove context (may be fine): {e}")

    return findings
