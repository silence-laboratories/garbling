use std::sync::mpsc;
use std::sync::Mutex;

pub struct Communication {
    channels: Vec<(
        Mutex<Option<mpsc::Sender<Vec<u8>>>>,
        Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
        Mutex<Option<mpsc::Sender<Vec<bool>>>>,
        Mutex<Option<mpsc::Receiver<Vec<bool>>>>,
    )>,
}

impl Communication {
    pub fn new(num_threads: usize) -> Self {
        let mut channels = Vec::with_capacity(num_threads);
        for _ in 0..num_threads {
            channels.push((
                Mutex::new(None),
                Mutex::new(None),
                Mutex::new(None),
                Mutex::new(None),
            ));
        }
        Communication { channels }
    }

    pub fn set_channel(
        &self,
        sender_id: usize,
        receiver_id: usize,
        u8_sender: mpsc::Sender<Vec<u8>>,
        u8_receiver: mpsc::Receiver<Vec<u8>>,
        bool_sender: mpsc::Sender<Vec<bool>>,
        bool_receiver: mpsc::Receiver<Vec<bool>>,
    ) {
        let _ = receiver_id;
        let (u8_sender_mutex, u8_receiver_mutex, bool_sender_mutex, bool_receiver_mutex) =
            &self.channels[sender_id];
        *u8_sender_mutex.lock().unwrap() = Some(u8_sender);
        *u8_receiver_mutex.lock().unwrap() = Some(u8_receiver);
        *bool_sender_mutex.lock().unwrap() = Some(bool_sender);
        *bool_receiver_mutex.lock().unwrap() = Some(bool_receiver);
    }

    pub fn send(&self, sender_id: usize, receiver_id: usize, data: &[u8]) {
        let _ = receiver_id;
        if let Some(sender) = self.channels[sender_id].0.lock().unwrap().as_ref() {
            sender.send(data.to_vec()).unwrap();
        } else {
            panic!("Sender channel is not set up for thread {}", sender_id);
        }
    }

    pub fn recv(&self, receiver_id: usize, sender_id: usize) -> Vec<u8> {
        let _ = sender_id;
        if let Some(receiver) = self.channels[receiver_id].1.lock().unwrap().as_ref() {
            receiver.recv().unwrap()
        } else {
            panic!("Receiver channel is not set up for thread {}", receiver_id);
        }
    }

    pub fn send_bool(&self, sender_id: usize, receiver_id: usize, data: &[bool]) {
        let _ = receiver_id;
        if let Some(sender) = self.channels[sender_id].2.lock().unwrap().as_ref() {
            sender.send(data.to_vec()).unwrap();
        } else {
            panic!("Sender channel is not set up for thread {}", sender_id);
        }
    }

    pub fn recv_bool(&self, receiver_id: usize, sender_id: usize) -> Vec<bool> {
        let _ = sender_id;
        if let Some(receiver) = self.channels[receiver_id].3.lock().unwrap().as_ref() {
            receiver.recv().unwrap()
        } else {
            panic!("Receiver channel is not set up for thread {}", receiver_id);
        }
    }
}