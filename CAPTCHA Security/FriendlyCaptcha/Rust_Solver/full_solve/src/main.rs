use base64::{engine::general_purpose, Engine as _};
use blake2b_simd::Params;
use reqwest;
use serde_json::Value;
use std::convert::TryInto;
use std::error::Error;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use threadpool::ThreadPool;

fn fetch_puzzle(url: &str) -> Result<String, Box<dyn Error>> {
    // Send a synchronous GET request to the URL
    let response = reqwest::blocking::get(url)?.text()?;

    // Parse the JSON response
    let json: Value = serde_json::from_str(&response)?;

    // Extract the puzzle string
    if json["success"].as_bool().unwrap_or(false) {
        Ok(json["data"]["puzzle"].as_str().unwrap_or("").to_string())
    } else {
        Err("Failed to fetch or parse the puzzle".into())
    }
}

fn split_and_decode(input: &str) -> Vec<u8> {
    let parts: Vec<&str> = input.split('.').collect();

    let decoded = general_purpose::STANDARD.decode(parts[1]).unwrap();

    return decoded;
}

fn create_puzzles(input: &[u8], number_of_puzzles: u8, puzzle_array: &mut [Vec<u8>]) {
    for i in 0..number_of_puzzles as usize {
        // Ensure the puzzle is of the correct size
        puzzle_array[i].resize(128, 0);

        // Copy the first 32 bytes of the input into the puzzle
        puzzle_array[i][..32].copy_from_slice(&input[..32]);

        // Adjust index 120
        puzzle_array[i][120] = i as u8;
    }
}

fn calculate_difficulty_threshold(d: u8) -> u32 {
    let base: f64 = 2.0;
    let exponent: f64 = (255.999 - d as f64) / 8.0;
    base.powf(exponent) as u32
}

fn solve_puzzle(puzzle: &mut Vec<u8>, threshold: u32) -> Vec<u8> {
    loop {
        let hash = Params::new()
            .hash_length(32)
            .to_state()
            .update(puzzle)
            .finalize()
            .as_bytes()
            .to_owned();

        let threshold_comparison = u32::from_le_bytes(hash[0..4].try_into().unwrap());

        if threshold_comparison < threshold {
            return puzzle[puzzle.len() - 8..].to_vec();
        }

        let last_four_bytes = &mut puzzle[124..128];
        let mut value = u32::from_le_bytes(last_four_bytes.try_into().unwrap());
        value = value.wrapping_add(1);
        last_four_bytes.copy_from_slice(&value.to_le_bytes());
    }
}

fn concatenate_and_encode(nonces: &[Vec<u8>]) -> String {
    let mut concatenated_bytes = Vec::new();

    // Directly concatenate each nonce
    for nonce in nonces {
        concatenated_bytes.extend_from_slice(nonce);
    }
    // Encode the concatenated bytes using Base64
    let encoded = general_purpose::STANDARD.encode(&concatenated_bytes);
    
    return encoded;
}

fn send_post_request(encoded_string: &str, url: &str) -> Result<(), Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();

    // Construct the body of the request
    let body = format!(
        "name=John+Doe&feedback=&thoughts=&frc-captcha-solution={}",
        encoded_string
    );

    // Send a POST request
    client
        .post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()?;

    Ok(())
}

fn main() {
    let api_get_endpoint = "https://api.friendlycaptcha.com/api/v1/puzzle?sitekey=FCMGEMUD2KTDSQ5H";
    let api_post_endpoint = "https://friendlycaptcha.com/demo";

    for _ in 0..4 {
        let puzzle_string = match fetch_puzzle(api_get_endpoint) {
            Ok(puzzle) => puzzle,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };

        // Split and decode to get the byte buffer
        let decoded = split_and_decode(&puzzle_string);

        // Get threshold and puzzle number
        let number_of_puzzles = decoded[14];
        let threshold_base = decoded[15];

        // Calculate real threshold
        let threshold = calculate_difficulty_threshold(threshold_base);

        // Array to hold the puzzles
        let mut puzzles: Vec<Vec<u8>> = vec![vec![0; 121]; number_of_puzzles as usize];

        // Create puzzles
        create_puzzles(&decoded, number_of_puzzles, &mut puzzles);

        let n_workers = num_cpus::get();
        let pool = ThreadPool::new(n_workers);
        let (tx, rx) = mpsc::channel();

        let m_puzzles = Arc::new(Mutex::new(puzzles));

        for _ in 0..m_puzzles.lock().unwrap().len() {
            let tx = tx.clone();
            let puzzles = Arc::clone(&m_puzzles);
            pool.execute(move || {
                let mut puzzle = {
                    let mut puzzles = puzzles.lock().unwrap();
                    puzzles.pop().unwrap_or_else(|| vec![0u8; 128])
                };

                let nonce = solve_puzzle(&mut puzzle, threshold);
                tx.send((nonce[0], nonce)).expect("Could not send data");
            });
        }

        // Close the sending end and wait for threads to finish
        drop(tx);

        // Collect results
        let mut results: Vec<(u8, Vec<u8>)> = rx.iter().collect();

        // Sort the results by index
        results.sort_by_key(|&(first_byte, _)| first_byte);

        // Extract just the nonces, now sorted by their original puzzle index
        let sorted_nonces: Vec<Vec<u8>> = results.into_iter().map(|(_, nonce)| nonce).collect();

        let solution_string = concatenate_and_encode(&sorted_nonces);

        let final_solution = format!("{}.{}", puzzle_string, solution_string);

        match send_post_request(&final_solution, api_post_endpoint) {
            Ok(()) => println!("Solution send"),
            Err(e) => eprintln!("Error sending POST request: {}", e),
        };
    }
}
