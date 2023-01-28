use wasm_bindgen::prelude::*;
use issuer::HoloTimestamp;

#[wasm_bindgen]
pub fn add(left: usize, right: usize) -> String {
    "hey".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        // assert_eq!(result, 4);
    }
}
