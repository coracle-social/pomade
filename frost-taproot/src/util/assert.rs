// Mirrors ref/frost/src/util/assert.ts

use crate::Error;

pub fn ok(value: bool, message: &str) -> Result<(), Error> {
    if !value {
        Err(Error::Assertion(message.to_string()))
    } else {
        Ok(())
    }
}

pub fn is_included<T: PartialEq>(array: &[T], item: &T) -> Result<(), Error> {
    if !array.contains(item) {
        Err(Error::Assertion(
            "item is not included in array".to_string(),
        ))
    } else {
        Ok(())
    }
}

pub fn is_unique_set<T: PartialEq + std::fmt::Debug>(array: &[T]) -> Result<(), Error> {
    for x in array {
        let count = array.iter().filter(|e| *e == x).count();
        if count != 1 {
            return Err(Error::Assertion(format!(
                "item in set is not unique: {:?}",
                x
            )));
        }
    }
    Ok(())
}

pub fn is_equal_set<T: PartialEq>(array: &[T]) -> Result<(), Error> {
    if !array.windows(2).all(|w| w[0] == w[1]) {
        Err(Error::Assertion(
            "set does not have equal items".to_string(),
        ))
    } else {
        Ok(())
    }
}

pub fn equal_arr_size<T, U>(a: &[T], b: &[U]) -> Result<(), Error> {
    if a.len() != b.len() {
        Err(Error::Assertion(format!(
            "array lengths are unequal: {} !== {}",
            a.len(),
            b.len()
        )))
    } else {
        Ok(())
    }
}
