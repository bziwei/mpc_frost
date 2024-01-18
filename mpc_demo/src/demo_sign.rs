pub const TX_HASH: &str = "0db666ad5f01d64a62e81fc3284e3b00851ccef419ad9dbc3273d75e01aad102";

#[tokio::main] // `tokio` re-exported by `mpc_sesman::prelude::*`
async fn main() -> Outcome<()> {
    let matches = Command::new("demo_keygen")
        .arg(
            Arg::new("signer_id")
                .short('s')
                .required(true)
                .value_parser(value_parser!(u16))
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("n_signers")
                .short('n')
                .default_value("3")
                .value_parser(value_parser!(u16))
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("member_id")
                .short('m')
                .required(true)
                .value_parser(value_parser!(u16))
                .action(ArgAction::Set),
        )
        .get_matches();

    let signer_id = *matches.get_one::<u16>("signer_id").ifnone_()?;
    let n_signers = *matches.get_one::<u16>("n_signers").ifnone_()?;
    let member_id = *matches.get_one::<u16>("member_id").ifnone_()?;
    println!("signer_id: {signer_id}, n_signers: {n_signers}, member_id: {member_id}");

    let keystore: KeyStore = {
        let path = &format!("assets/{}@demo_keygen.keystore", member_id);
        let mut file = File::open(path).await.catch_()?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).await.catch_()?;
        let keystore = serde_json::from_slice(&buf).catch_()?;
        keystore
    };
    let tx_hash = hex::decode(TX_HASH).catch_()?;
    let signature = algo_sign(&keystore, signer_id, n_signers, "m/1/14/514", &tx_hash)
        .await
        .catch_()?;
    println!("{signature:?}");

    Ok(())
}

use clap::{value_parser, Arg, ArgAction, Command};
use mpc_algo_sdk::{algo_sign, KeyStore};
use mpc_sesman::prelude::tokio::{fs::File, io::AsyncReadExt};
use mpc_sesman::prelude::*;
