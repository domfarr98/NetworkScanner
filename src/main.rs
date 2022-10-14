use qscan::{QSPrintMode, QScanResult, QScanTcpConnectState, QScanType, QScanner};
use tokio::runtime::Runtime;

fn main() {

    let mut addresses = "".to_string();

    for n in 0..256
    {
        addresses.push_str("192.168.1.");
        addresses.push_str(&n.to_string());
        if n != 255
        {
            addresses.push_str(",");
        }
    }

    let mut scanner = QScanner::new(&addresses, "53,80,443");
    scanner.set_batch(5000);
    scanner.set_timeout_ms(2000);
    scanner.set_ntries(1);
    scanner.set_scan_type(QScanType::TcpConnect);
    scanner.set_print_mode(QSPrintMode::NonRealTime);

    let res: &Vec<QScanResult> = Runtime::new().unwrap().block_on(scanner.scan_tcp_connect());

    for r in res
    {
        if let QScanResult::TcpConnect(sa) = r
        {
            if sa.state == QScanTcpConnectState::Open
            {
                println!("{}", sa.target);
            }
        }
    }
}
