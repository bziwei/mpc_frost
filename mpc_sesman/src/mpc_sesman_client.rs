pub mod exception;
pub mod prelude {
    pub use crate::exception::*;
    pub use crate::{assert_throw, throw};
    pub use crate::{
        gather_p2p, gather_p2p_all, recv_bcast_wo_src, recv_bcast, recv_p2p, send_bcast,
        send_p2p, Message, PARTY_ID_BCAST,
    };
    pub use tokio;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub src: u16,
    pub dst: u16,
    pub round: String,
    pub obj: Option<Vec<u8>>,
}

pub async fn send_bcast<T>(src: u16, round: &str, obj: &T) -> Outcome<()>
where
    T: Serialize + DeserializeOwned,
{
    let obj = obj.compress().catch_()?;
    let msg = Message {
        src,
        dst: PARTY_ID_BCAST,
        round: round.to_string(),
        obj: Some(obj),
    };
    let client = reqwest::Client::new();
    let _void = client.post(URL_SEND).json(&msg).send().await.catch_()?;
    Ok(())
}

pub async fn send_p2p<T>(src: u16, dst: u16, round: &str, obj: &T) -> Outcome<()>
where
    T: Serialize + DeserializeOwned,
{
    let obj = obj.compress().catch_()?;
    let msg = Message {
        src,
        dst,
        round: round.to_string(),
        obj: Some(obj),
    };
    let client = reqwest::Client::new();
    let _void = client.post(URL_SEND).json(&msg).send().await.catch_()?;
    Ok(())
}

/// exclude src
pub async fn recv_bcast_wo_src<T>(exclude_src: u16, n_members: u16, round: &str) -> Outcome<Vec<T>>
where
    T: Serialize + DeserializeOwned,
{
    let client = reqwest::Client::new();
    let mut ret: Vec<T> = Vec::with_capacity(n_members as usize - 1);
    '_outer: for id in 1..=n_members {
        if id == exclude_src {
            continue;
        }
        let index = Message {
            src: id,
            dst: PARTY_ID_BCAST,
            round: round.to_string(),
            obj: None,
        };
        'inner: loop {
            let req = client.post(URL_RECV).json(&index);
            let resp = req.send().await.catch_()?;
            let msg: Message = resp.json().await.catch_()?;
            match msg.obj {
                Some(obj) => {
                    let obj = obj.decompress().catch_()?;
                    ret.push(obj);
                    break 'inner;
                }
                None => {
                    use tokio::time::{sleep, Duration};
                    sleep(Duration::from_millis(DEFAULT_POLL_SLEEP_MS)).await;
                }
            }
        }
    }
    Ok(ret)
}

pub async fn recv_bcast<T>(n_members: u16, round: &str) -> Outcome<Vec<T>>
where
    T: Serialize + DeserializeOwned,
{
    let client = reqwest::Client::new();
    let mut ret: Vec<T> = Vec::with_capacity(n_members as usize - 1);
    '_outer: for id in 1..=n_members {
        let index = Message {
            src: id,
            dst: PARTY_ID_BCAST,
            round: round.to_string(),
            obj: None,
        };
        'inner: loop {
            let req = client.post(URL_RECV).json(&index);
            let resp = req.send().await.catch_()?;
            let msg: Message = resp.json().await.catch_()?;
            match msg.obj {
                Some(obj) => {
                    let obj = obj.decompress().catch_()?;
                    ret.push(obj);
                    break 'inner;
                }
                None => {
                    use tokio::time::{sleep, Duration};
                    sleep(Duration::from_millis(DEFAULT_POLL_SLEEP_MS)).await;
                }
            }
        }
    }
    Ok(ret)
}

pub async fn recv_p2p<T>(src: u16, dst: u16, round: &str) -> Outcome<T>
where
    T: Serialize + DeserializeOwned,
{
    let client = reqwest::Client::new();
    let index = Message {
        src,
        dst,
        round: round.to_string(),
        obj: None,
    };
    loop {
        let req = client.post(URL_RECV).json(&index);
        let resp = req.send().await.catch_()?;
        let msg: Message = resp.json().await.catch_()?;
        match msg.obj {
            Some(obj) => {
                let obj = obj.decompress().catch_()?;
                return Ok(obj);
            }
            None => {
                use tokio::time::{sleep, Duration};
                sleep(Duration::from_millis(DEFAULT_POLL_SLEEP_MS)).await;
            }
        }
    }
}

/// Exclude the message whose src == dst
pub async fn gather_p2p<T>(dst: u16, n_members: u16, round: &str) -> Outcome<Vec<T>>
where
    T: Serialize + DeserializeOwned,
{
    let mut ret: Vec<T> = Vec::with_capacity(n_members as usize - 1);
    for src in 1..=n_members {
        if src == dst {
            continue;
        }
        let obj: T = recv_p2p(src, dst, round).await.catch_()?;
        ret.push(obj);
    }
    Ok(ret)
}

/// Include the message whose src == dst
pub async fn gather_p2p_all<T>(dst: u16, n_members: u16, round: &str) -> Outcome<Vec<T>>
where
    T: Serialize + DeserializeOwned,
{
    let mut ret: Vec<T> = Vec::with_capacity(n_members as usize - 1);
    for src in 1..=n_members {
        let obj: T = recv_p2p(src, dst, round).await.catch_()?;
        ret.push(obj);
    }
    Ok(ret)
}

trait CompressAble {
    fn compress(&self) -> Outcome<Vec<u8>>;
}

trait DecompressAble<T> {
    fn decompress(&self) -> Outcome<T>;
}

impl<T> CompressAble for T
where
    T: Serialize + DeserializeOwned,
{
    fn compress(&self) -> Outcome<Vec<u8>> {
        let json = serde_json::to_string(&self).catch_()?;
        let bytes = compress_to_vec(json.as_bytes(), 7);
        Ok(bytes)
    }
}

impl<S, D> DecompressAble<D> for S
where
    S: AsRef<[u8]>,
    D: Serialize + DeserializeOwned,
{
    fn decompress(&self) -> Outcome<D> {
        let bytes = decompress_to_vec(self.as_ref()).catch_()?;
        let json = String::from_utf8(bytes).catch_()?;
        let obj = serde_json::from_str(&json).catch_()?;
        Ok(obj)
    }
}

use crate::prelude::*;
use miniz_oxide::{deflate::compress_to_vec, inflate::decompress_to_vec};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub const PARTY_ID_BCAST: u16 = 0;
const URL_SEND: &'static str = "http://127.0.0.1:14514/postmsg";
const URL_RECV: &'static str = "http://127.0.0.1:14514/getmsg";
const DEFAULT_POLL_SLEEP_MS: u64 = 200;
