use crate::db;

pub async fn calculate_core_hours_per_hour(
    cpu_cores: i32,
    memory_gb: f64,
    bandwidth_mbps: f64,
    disk_gb: f64,
    cpu_multiplier: f64,
    memory_multiplier: f64,
    bandwidth_multiplier: f64,
    disk_multiplier: f64,
    nat_ports: i32,
    nat_multiplier: f64,
) -> f64 {
    let global_cpu = db::get_config("global_cpu_multiplier")
        .await
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(1.0);
    let global_mem = db::get_config("global_memory_multiplier")
        .await
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(1.0);
    let global_bw = db::get_config("global_bandwidth_multiplier")
        .await
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(1.0);
    let global_disk = db::get_config("global_disk_multiplier")
        .await
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(1.0);
    let global_nat = db::get_config("global_nat_multiplier")
        .await
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(1.0);

    cpu_cores as f64 * cpu_multiplier * global_cpu
        + memory_gb * memory_multiplier * global_mem
        + bandwidth_mbps * bandwidth_multiplier * global_bw
        + disk_gb * disk_multiplier * global_disk
        + nat_ports as f64 * nat_multiplier * global_nat
}