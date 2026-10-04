//! Allocation-free shape validation before Serde sees any attacker-controlled
//! collection size hint. Indefinite containers and semantic tags are not wire features.
use crate::codec::CodecError;

pub fn validate(bytes: &[u8]) -> Result<(), CodecError> {
    let mut parser = Parser {
        bytes,
        offset: 0,
        remaining_items: 131_072,
    };
    parser.item(0)?;
    if parser.offset != bytes.len() {
        return Err(CodecError::Body);
    }
    Ok(())
}

struct Parser<'a> {
    bytes: &'a [u8],
    offset: usize,
    remaining_items: usize,
}
impl Parser<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8], CodecError> {
        let end = self
            .offset
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(CodecError::Body)?;
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }
    fn argument(&mut self, additional: u8) -> Result<u64, CodecError> {
        let count = match additional {
            0..=23 => return Ok(u64::from(additional)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(CodecError::Body),
        };
        Ok(self
            .take(count)?
            .iter()
            .fold(0, |value, byte| (value << 8) | u64::from(*byte)))
    }
    fn item(&mut self, depth: u8) -> Result<(), CodecError> {
        if depth >= 32 || self.remaining_items == 0 {
            return Err(CodecError::Limit);
        }
        self.remaining_items -= 1;
        let initial = self.take(1)?[0];
        let major = initial >> 5;
        let argument = self.argument(initial & 31)?;
        match major {
            0 | 1 | 7 => Ok(()),
            2 | 3 => {
                self.take(usize::try_from(argument).map_err(|_| CodecError::Limit)?)?;
                Ok(())
            }
            4 | 5 => {
                let limit = if major == 5 { 512 } else { 65_536 };
                if argument > limit {
                    return Err(CodecError::Limit);
                }
                let children = usize::try_from(argument).map_err(|_| CodecError::Limit)?
                    * if major == 5 { 2 } else { 1 };
                if children > self.remaining_items || children > self.bytes.len() - self.offset {
                    return Err(CodecError::Limit);
                }
                for _ in 0..children {
                    self.item(depth + 1)?;
                }
                Ok(())
            }
            _ => Err(CodecError::Body),
        }
    }
}
