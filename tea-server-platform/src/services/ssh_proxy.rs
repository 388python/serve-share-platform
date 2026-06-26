use std::collections::HashMap;
use std::sync::Mutex;

static PORT_ALLOCATIONS: Mutex<Option<HashMap<i64, u16>>> = Mutex::new(None);
static NEXT_PORT: Mutex<Option<u16>> = Mutex::new(None);

fn init() {
    let mut next = NEXT_PORT.lock().unwrap();
    if next.is_none() {
        *next = Some(30000);
    }
    let mut ports = PORT_ALLOCATIONS.lock().unwrap();
    if ports.is_none() {
        *ports = Some(HashMap::new());
    }
}

pub fn allocate_port(server_id: i64) -> u16 {
    init();
    let mut ports = PORT_ALLOCATIONS.lock().unwrap();
    let mut next = NEXT_PORT.lock().unwrap();
    let port = next.unwrap();
    *next = Some(port + 1);
    ports.as_mut().unwrap().insert(server_id, port);
    port
}

pub fn release_port(server_id: i64) {
    init();
    let mut ports = PORT_ALLOCATIONS.lock().unwrap();
    ports.as_mut().unwrap().remove(&server_id);
}

pub fn allocate_port_with_id(server_id: i64, port: u16) {
    init();
    let mut ports = PORT_ALLOCATIONS.lock().unwrap();
    ports.as_mut().unwrap().insert(server_id, port);
}

#[allow(dead_code)]
pub fn get_port(server_id: i64) -> Option<u16> {
    init();
    PORT_ALLOCATIONS.lock().unwrap().as_ref().unwrap().get(&server_id).copied()
}