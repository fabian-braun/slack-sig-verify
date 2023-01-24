fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use ring::hmac;

    #[test]
    fn test_verify_signature_raw_works_for_slack_example() {
        // See example here: https://api.slack.com/authentication/verifying-requests-from-slack
        let body = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
        let timestamp = "1531420618";
        let expected_sig = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";
        let signing_key = "8f742231b10e8888abcd99yyyzzz85a5";

        // strip the prefix from the expected signature first
        let expected_sig = expected_sig.strip_prefix("v0=").unwrap();
        // hex-decode the result to a byte-slice
        let expected_sig = hex::decode(expected_sig).unwrap();
        // use as_bytes on timestamp and signing_key (these are no hex-Strings)
        let timestamp = timestamp.as_bytes();
        let signing_key = signing_key.as_bytes();
        // initialize the hmac Key
        let signing_key = hmac::Key::new(hmac::HMAC_SHA256, signing_key);
        let delimiter = ":".as_bytes();
        let version = "v0".as_bytes();
        // concatenate all the prepared bytes-slices
        let input = [version, delimiter, timestamp, delimiter, body.as_bytes()].concat();
        // feed the prepared data into hmac::verify
        hmac::verify(&signing_key, &input, &expected_sig)?;
        // protecting against replay attacks is still required on top of this!
        let expected = Ok(());
        assert_eq!(expected, actual);
    }
}