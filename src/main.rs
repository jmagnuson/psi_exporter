use std::collections::HashMap;
use std::fs;
use std::net;

use std::io::Read;

use prometheus::Encoder;

const MOUNTPOINT: &str = "/sys/fs/cgroup";
const PRESSURE_SUFFIX: &str = ".pressure";

fn main() {
    let matches = clap::App::new(clap::crate_name!())
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .about(clap::crate_description!())
        .arg(
            clap::Arg::with_name("web.listen-address")
                .help("Address on which to expose metrics and web interface")
                .long("web.listen-address")
                .validator(|v| {
                    v.parse::<net::SocketAddr>()
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                })
                .takes_value(true)
                .default_value("[::1]:12345"),
        )
        .arg(
            clap::Arg::with_name("metrics.disable-avg")
                .help("Disable reporting of average values")
                .long("metrics.disable-avg")
                .takes_value(false),
        )
        .arg(
            clap::Arg::with_name("metrics.silence-zeros")
                .help("Do not report zero values")
                .long("metrics.silence-zeros")
                .takes_value(false),
        )
        .arg(
            clap::Arg::with_name("metrics.docker-scopes")
                .help("Include docker-created cgroup scopes using container names")
                .long("metrics.docker-scopes")
                .takes_value(false),
        )
        .get_matches();

    let addr = &matches.value_of("web.listen-address").unwrap();

    let report_avg = !matches.is_present("metrics.disable-avg");
    let report_zeros = !matches.is_present("metrics.silence-zeros");

    let docker_scopes = matches.is_present("metrics.docker-scopes");

    println!("Listening address: {}", addr);

    let server = tiny_http::Server::http(addr).unwrap();

    let encoder = prometheus::TextEncoder::new();
    let content_type = tiny_http::Header::from_bytes(
        &b"Content-type"[..],
        encoder.format_type().to_owned().as_str(),
    )
    .unwrap();

    for request in server.incoming_requests() {
        let metrics = registry(&get_service_measurements(docker_scopes), report_avg, report_zeros).gather();
        let mut buffer = vec![];
        encoder.encode(&metrics, &mut buffer).unwrap();

        request
            .respond(tiny_http::Response::from_data(buffer).with_header(content_type.clone()))
            .unwrap_or_else(|e| eprintln!("error responding: {}", e));
    }
}

fn registry(
    service_measurements: &HashMap<String, PsiMeasurements>,
    report_avg: bool,
    report_zeros: bool,
) -> prometheus::Registry {
    let registry = prometheus::Registry::new();
    let labels = &["id", "controller", "kind"];

    let total = counter_vec(
        "pressure_total_seconds",
        "Total time spent under pressure",
        labels,
    );

    registry.register(Box::new(total.clone())).unwrap();

    let avg10 = gauge_vec(
        "pressure_avg_10s_ratio",
        "Ratio of time spent under pressure in the last 10s at time of measurement",
        labels,
    );

    let avg60 = gauge_vec(
        "pressure_avg_60s_ratio",
        "Ratio of time spent under pressure in the last 60s at time of measurement",
        labels,
    );

    let avg300 = gauge_vec(
        "pressure_avg_300s_ratio",
        "Ratio of time spent under pressure in the last 300s at time of measurement",
        labels,
    );

    let averages = vec![&avg10, &avg60, &avg300];

    for metric in averages {
        registry.register(Box::new(metric.clone())).unwrap();
    }

    for (service, measurements) in service_measurements {
        let controllers = maplit::hashmap! {
            "cpu"    => &measurements.cpu,
            "memory" => &measurements.memory,
            "io"     => &measurements.io,
        };

        for (controller, measurement) in controllers {
            let kinds = maplit::hashmap! {
                "some" => measurement.some.as_ref(),
                "full" => measurement.full.as_ref(),
            };

            for (kind, data) in kinds.into_iter().filter_map(|(kind, data_opt)| {
                if let Some(data) = data_opt {
                    Some((kind, data))
                } else {
                    None
                }
            }) {
                let labels = &[service.as_str(), controller, kind];

                if report_zeros || data.total.as_nanos() > 0 {
                    total
                        .with_label_values(labels)
                        .inc_by((data.total.as_nanos() as f64) / 1e9);
                }

                if report_avg {
                    if report_zeros || data.avg10 > 0.0 {
                        avg10
                            .with_label_values(labels)
                            .set(f64::from(data.avg10) / 100.0);
                    }

                    if report_zeros || data.avg60 > 0.0 {
                        avg60
                            .with_label_values(labels)
                            .set(f64::from(data.avg60) / 100.0);
                    }

                    if report_zeros || data.avg300 > 0.0 {
                        avg300
                            .with_label_values(labels)
                            .set(f64::from(data.avg300) / 100.0);
                    }
                }
            }
        }
    }

    registry
}

fn counter_vec(name: &str, help: &str, labels: &[&str]) -> prometheus::CounterVec {
    prometheus::CounterVec::new(prometheus::opts!(name, help), labels).unwrap()
}

fn gauge_vec(name: &str, help: &str, labels: &[&str]) -> prometheus::GaugeVec {
    prometheus::GaugeVec::new(prometheus::opts!(name, help), labels).unwrap()
}

macro_rules! skip_fail {
    ($res:expr) => {
        match $res {
            Ok(val) => val,
            Err(_) => continue,
        }
    };
}

fn get_service_measurements(docker_scopes: bool) -> HashMap<String, PsiMeasurements> {
    let mut services: HashMap<_, PsiMeasurements> = HashMap::new();

    for entry in walkdir::WalkDir::new(MOUNTPOINT)
        .into_iter()
        .filter_entry(|e| is_interesting(e, docker_scopes))
        .filter_map(|e_res| match e_res {
            Ok(e) if is_pressure(&e) => Some(e),
            _ => None,
        })
    {
        let path = entry.path();

        let dir_name = {
            let parent = path.parent().unwrap().strip_prefix(MOUNTPOINT).unwrap();

            let mut dir_name = std::path::Path::new("/")
                .join(parent)
                .to_str()
                .unwrap()
                .to_string();

            if let Some(parent_filename) = parent.file_name() {
                if is_interesting_scope(parent_filename.to_str().unwrap(), docker_scopes) {
                    // docker lookup is somewhat expensive
                    if let Some(new_dir) = map_docker_scope(dir_name.as_str()) {
                        dir_name = new_dir;
                    }
                }
            }

            dir_name
        };

        let mut controller = path.file_name().unwrap().to_str().unwrap().to_string();

        controller.truncate(controller.len() - PRESSURE_SUFFIX.len());

        let mut file = skip_fail!(fs::OpenOptions::new().read(true).open(path));
        let mut buf = String::with_capacity(256);
        skip_fail!(file.read_to_string(&mut buf));

        let mut some = None;
        let mut full = None;

        for line in buf.lines() {
            let parsed: Result<psi::Psi, _> = line.parse();
            let parsed = parsed.unwrap();

            match parsed.line {
                psi::PsiLine::Some => some = Some(parsed),
                psi::PsiLine::Full => full = Some(parsed),
            };
        }

        populate_measurements(
            &controller,
            services.entry(dir_name).or_default(),
            PsiStats { some, full },
        );
    }

    services
}

fn populate_measurements(
    controller: &str,
    measurements: &mut PsiMeasurements,
    measurement: PsiStats,
) {
    match controller {
        "cpu" => measurements.cpu = measurement,
        "memory" => measurements.memory = measurement,
        "io" => measurements.io = measurement,
        _ => (),
    }
}

fn is_interesting_scope(s: &str, docker_scopes: bool) -> bool {
    let starts_docker = s.starts_with("docker-");
    let ends_scope = s.ends_with(".scope");
    match (docker_scopes, starts_docker, ends_scope) {
        (true, true, true) => true,
        _ => false,
    }
}

fn is_interesting(entry: &walkdir::DirEntry, docker_scopes: bool) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| !(s.ends_with(".mount") || s.ends_with(".socket")) || is_interesting_scope(s, docker_scopes))
        .unwrap_or(false)
}

fn map_docker_scope(s: &str) -> Option<String> {
    fn extract_id(input: &str) -> Option<&str> {
        input
            .strip_prefix("docker-")
            .and_then(|s| s.strip_suffix(".scope"))
    }

    fn get_container_name(container_id: &str) -> Option<String> {
        let output = std::process::Command::new("docker")
            .args(["inspect", "--format", "{{.Name}}", container_id])
            .output();

        match output {
            Ok(output) if output.status.success() => {
                let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
                Some(name.trim_start_matches('/').to_string()) // Remove leading `/`
            }
            Ok(output) => {
                eprintln!(
                    "Docker error: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
                None
            }
            Err(e) => {
                eprintln!("Failed to execute docker command: {}", e);
                None
            }
        }
    }

    let mut path = std::path::PathBuf::from(s);

    let id = {
        let scope = path.file_name()?.to_str()?;
        extract_id(scope)?
    };

    let name = get_container_name(id)?;

    // let mut path = std::path::PathBuf::from(s);
    path.set_file_name(format!("docker-{name}.scope"));

    Some(path.display().to_string())
}

fn is_pressure(entry: &walkdir::DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.ends_with(PRESSURE_SUFFIX))
        .unwrap_or(false)
}

#[derive(Debug, Default)]
struct PsiStats {
    some: Option<psi::Psi>,
    full: Option<psi::Psi>,
}

#[derive(Debug, Default)]
struct PsiMeasurements {
    cpu: PsiStats,
    memory: PsiStats,
    io: PsiStats,
}
