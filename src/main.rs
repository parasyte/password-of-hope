//! The Password of Hope
//!
//! Generate and decode any password for The Sword of Hope.

use bitflags::bitflags;
use colorz::{Colorize as _, mode::set_coloring_mode_from_env};
use error_iter::ErrorIter as _;
use onlyargs::OnlyArgs;
use onlyargs_derive::OnlyArgs;
use onlyerror::Error;
use std::io::{self, Write};
use std::{fmt, process::ExitCode};

const CHARSET: &str = "BCDFGHJKLMNPQRSTVWXYZ∞▽△12345ΛΩΞ";
const DIFFS: &[u8] = &[
    0x00, 0x05, 0x10, 0x07, 0x08, 0x06, 0x14, 0x09, 0x13, 0x07, 0x11, 0xa, 0x03, 0x16, 0x08, 0x15,
];
const PASSWORD_LENGTH: usize = 16;
const PASSWORD_STATE_LENGTH: usize = 10;

#[derive(Debug, Error)]
enum Error {
    /// CLI error
    Cli(#[from] onlyargs::CliError),

    /// Invalid password character
    #[error("Invalid password character: `{0}`")]
    InvalidCharacter(char),

    /// Invalid password checksum
    InvalidChecksum,

    /// Password requires 16 characters
    PasswordLength,

    /// Password state requires 9 bytes
    StateLength,

    /// Invalid hex digits
    #[error("Invalid hex digits: `{0}`")]
    InvalidHex(String),
}

impl Error {
    /// Check if the error was caused by CLI inputs.
    fn is_cli(&self) -> bool {
        matches!(self, Self::Cli(_))
    }
}

/// Password Character Set:
///
///   B C D F G H J K L M N P Q R S T V W X Y Z ∞ ▽ △ 1 2 3 4 5 Λ Ω Ξ
///
/// For simplicity, ASCII character substitutions are available:
///   - ∞ : 8
///   - ▽ : -
///   - △ : +
///   - Λ : ^
///   - Ω : O
///   - Ξ : =
#[derive(Debug, OnlyArgs)]
struct Args {
    /// Decode a password.
    decode: Option<String>,

    /// Encode password state.
    encode: Option<String>,

    /// Enable verbose output.
    verbose: bool,
}

fn main() -> ExitCode {
    set_coloring_mode_from_env();

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if error.is_cli() {
                let _ = writeln!(io::stderr(), "{}", Args::HELP);
            }

            let _ = writeln!(io::stderr(), "{}: {error}", "Error".bright_red());
            for source in error.sources().skip(1) {
                let _ = writeln!(io::stderr(), "  {}: {source}", "Caused by".bright_yellow());
            }

            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Error> {
    let args: Args = onlyargs::parse()?;

    if args.decode.is_none() && args.encode.is_none() {
        Args::help();
    }

    let mut stdout = io::stdout();
    if let Some(password) = args.decode {
        decoder(&mut stdout, &password, args.verbose)?;
    }
    if let Some(state) = args.encode {
        encoder(&mut stdout, &state, args.verbose)?;
    }

    Ok(())
}

/// Attempt to decode and validate a password.
fn decoder<W: Write>(writer: &mut W, password: &str, verbose: bool) -> Result<(), Error> {
    let mut base32 = [0_u8; PASSWORD_STATE_LENGTH];
    let mut bit_index = 0;
    let mut ch1 = 0;
    let mut i = 0;
    for ch in password.to_uppercase().chars() {
        let ch = match ch {
            '8' => '∞',
            '-' => '▽',
            '+' => '△',
            '^' => 'Λ',
            'O' => 'Ω',
            '=' => 'Ξ',
            ch => ch,
        };
        if ch == ' ' {
            continue;
        } else if i >= PASSWORD_LENGTH {
            return Err(Error::PasswordLength);
        }

        let Some(ch) = CHARSET.chars().position(|chr| chr == ch) else {
            return Err(Error::InvalidCharacter(ch));
        };
        let ch = ch as u8;
        let diff = DIFFS[i];
        let input = if diff > 0 {
            deobfuscate(ch1, ch, diff)
        } else {
            ch1 = ch;

            ch
        };

        encode_b32(&mut base32, bit_index, input);
        bit_index += 5;
        i += 1;
    }
    if i != PASSWORD_LENGTH {
        return Err(Error::PasswordLength);
    }

    let chk = checksum(&base32);
    if verbose {
        let _ = write!(writer, "Decoded: ");
        for byte in &base32 {
            let _ = write!(writer, "{byte:02x} ");
        }
        let _ = writeln!(writer);

        let _ = writeln!(writer, "Checksum: {:02x}", chk);
    }

    if chk != base32[0] {
        return Err(Error::InvalidChecksum);
    }

    let _ = write!(writer, "State: ");
    for byte in &base32[1..] {
        let _ = write!(writer, "{byte:02x} ");
    }
    let _ = writeln!(writer);

    let _ = writeln!(writer);
    let _ = writeln!(writer, "{}", State::from(&base32[..]));

    Ok(())
}

/// Packs 5-bit characters into 8-bit bytes.
fn encode_b32(base32: &mut [u8], bit_index: usize, ch: u8) {
    let i = bit_index / 8;
    let j = bit_index % 8;

    // First half.
    base32[i] |= if j <= 3 { ch << (3 - j) } else { ch >> (j - 3) };

    if j > 3 {
        // Second half.
        let k = ((j - 4) ^ 3) + 4;
        base32[i + 1] |= ch << k;
    }
}

/// Uses the "difference table" to deobfuscate each byte of password state.
fn deobfuscate(ch1: u8, ch: u8, diff: u8) -> u8 {
    ch.wrapping_sub(diff).wrapping_sub(ch1) & 0x1f
}

/// Encode password state into a valid password.
fn encoder<W: Write>(writer: &mut W, state: &str, verbose: bool) -> Result<(), Error> {
    let mut base32 = [0; PASSWORD_STATE_LENGTH];
    let mut i = 0;
    let mut pos = 1;
    while pos < PASSWORD_STATE_LENGTH {
        if state.get(i..i + 1) == Some(" ") {
            i += 1;

            continue;
        }

        let Some(octet) = state.get(i..i + 2) else {
            return Err(Error::StateLength);
        };
        let Ok(byte) = u8::from_str_radix(octet, 16) else {
            return Err(Error::InvalidHex(octet.to_string()));
        };
        base32[pos] = byte;

        pos += 1;
        i += 2;
    }
    if !matches!(state.get(i..).map(|tail| tail.trim()), None | Some("")) {
        return Err(Error::StateLength);
    }

    base32[0] = checksum(&base32);
    if verbose {
        let _ = writeln!(writer, "Checksum: {:02x}", base32[0]);
    }

    let _ = write!(writer, "State: ");
    for byte in &base32[1..] {
        let _ = write!(writer, "{byte:02x} ");
    }
    let _ = writeln!(writer);

    let _ = writeln!(writer);
    let _ = writeln!(writer, "{}", State::from(&base32[..]));

    let mut decoded = decode_b32(&base32);
    if verbose {
        let _ = write!(writer, "Decoded: ");
        for byte in &decoded {
            let _ = write!(writer, "{byte:02x} ");
        }
        let _ = writeln!(writer);
    }

    obfuscate(&mut decoded);
    if verbose {
        let _ = write!(writer, "Obfuscated: ");
        for byte in &decoded {
            let _ = write!(writer, "{byte:02x} ");
        }
        let _ = writeln!(writer);
    }

    let _ = write!(writer, "Password: ");
    for (i, byte) in decoded.iter().enumerate() {
        if i > 0 && (i % 4) == 0 {
            let _ = write!(writer, " ");
        }

        let pos = *byte as usize;
        let ch = CHARSET.chars().nth(pos).unwrap();

        let _ = write!(writer, "{ch}");
    }
    let _ = writeln!(writer);

    Ok(())
}

/// Unpacks 5-bit characters from 8-bit bytes.
fn decode_b32(base32: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    let mut bit_index = 0;

    while bit_index < 16 * 5 {
        let i = bit_index / 8;
        let j = bit_index % 8;

        if j <= 3 {
            // First half.
            decoded.push((base32[i] >> (3 - j)) & 0x1f);
        } else {
            // both halves.
            let k = ((j - 4) ^ 3) + 4;
            let hi = (base32[i] << (j - 3)) & 0x1f;
            let lo = (base32[i + 1] >> k) & 0x1f;

            decoded.push(hi | lo);
        }

        bit_index += 5;
    }

    decoded
}

/// Uses the "difference table" to obfuscate each byte of password state.
fn obfuscate(encoded: &mut [u8]) {
    for i in (1..16).rev() {
        encoded[i] = encoded[i].wrapping_add(DIFFS[i]).wrapping_add(encoded[0]) & 0x1f;
    }
}

/// Compute the password state checksum.
fn checksum(decoded: &[u8]) -> u8 {
    let mut sum: u8 = 0;

    for byte in decoded.iter().skip(1) {
        sum = sum.wrapping_add(*byte);
    }

    sum
}

/// Password State
///
/// Password state is 9 bytes in the following format:
///
/// | Byte 0   | Byte 1   | Byte 2   | Byte 3   | Byte 4   | Byte 5   | Byte 6   | Byte 7   | Byte 8   |
/// |----------|----------|----------|----------|----------|----------|----------|----------|----------|
/// | xxxxxxxx | xxxxllll | lggggggg | gbbbwwwh | hhsssaaG | !MSCWBRU | HONIATFP | DYVf.... | ......t. |
///
/// - `xxxxxxxxxxxx`: Experience points above bonus. `0 - 4,095`
/// - `lllll`: Level, magic, and stats bonuses. `1 - 32`
/// - `gggg`: Gold. `0 - 255`
/// - `bbb`: Barley. `0 - 7`
/// - `www`: Wheat. `0 - 7`
/// - `hhh`: Herb. `0 - 7`
/// - `sss`: Sword and base dexterity.
///     - `0`: Probite and 7 base dexterity.
///     - `1`: 3 Star and 17 base dexterity.
///     - `2`: Extra and 27 base dexterity.
///     - `3`: Adage and 47 base dexterity.
///     - `4`: Wish and 62 base dexterity.
///     - `5`: Copper and 7 base dexterity.
///     - `6`: Silver and 27 base dexterity.
///     - `7`: Gold and 47 base dexterity.
/// - `aa`: Armor and base stamina.
///     - `0`: Copper and 8 base stamina.
///     - `1`: Silver and 28 base stamina.
///     - `2`: Gold and 48 base stamina.
///     - `3`: Platinum and 68 base stamina.
/// - `G`: Grace (Magic).
/// - `!`: Secret (Magic).
/// - `M`: Key M.
/// - `S`: Key S.
/// - `C`: Key C.
/// - `W`: W Egg.
/// - `B`: B Egg.
/// - `R`: R Egg.
/// - `U`: Ruby.
/// - `H`: Charm.
/// - `O`: MoonFrag.
/// - `N`: Uni Horn.
/// - `I`: Ring.
/// - `A`: Sapphire.
/// - `T`: TrtFruit.
/// - `F`: FairyLmp.
/// - `P`: Spore.
/// - `D`: Doll.
/// - `Y`: Y Fruit.
/// - `V`: Ivy Seed.
/// - `f`: Event: Spoken to Forest Shop Mistress.
/// - `...`: TBD.
/// - `t`: Event: Met the trees.
///
/// The weakest password is `BHVK LJZM YKWN F▽L∞` and the strongest is `3KNC CΞRD MBNF 5LDT`.
#[derive(Debug)]
struct State {
    experience: u16,
    level: u8,
    gold: u8,
    barley: u8,
    wheat: u8,
    herb: u8,
    sword: Sword,
    armor: Armor,
    grace: bool,
    secret: bool,
    key_m: bool,
    key_s: bool,
    key_c: bool,
    w_egg: bool,
    b_egg: bool,
    r_egg: bool,
    ruby: bool,
    charm: bool,
    moon_frag: bool,
    uni_horn: bool,
    ring: bool,
    sapphire: bool,
    trt_fruit: bool,
    fairy_lmp: bool,
    spore: bool,
    doll: bool,
    y_fruit: bool,
    ivy_seed: bool,
    events: Events,
}

impl From<&[u8]> for State {
    fn from(state: &[u8]) -> Self {
        Self {
            experience: (state[1] as u16) << 4 | ((state[2] as u16) >> 4),
            level: ((state[2] << 1 | state[3] >> 7) & 0x1f) + 1,
            gold: state[3] << 1 | state[4] >> 7,
            barley: (state[4] >> 4) & 0x07,
            wheat: (state[4] >> 1) & 0x07,
            herb: (state[4] << 2 | state[5] >> 6) & 0x07,
            sword: Sword::from(state[5] >> 3 & 0x07),
            armor: Armor::from(state[5] >> 1 & 0x03),
            grace: state[5] & 0x01 != 0,
            secret: state[6] & 0x80 != 0,
            key_m: state[6] & 0x40 != 0,
            key_s: state[6] & 0x20 != 0,
            key_c: state[6] & 0x10 != 0,
            w_egg: state[6] & 0x08 != 0,
            b_egg: state[6] & 0x04 != 0,
            r_egg: state[6] & 0x02 != 0,
            ruby: state[6] & 0x01 != 0,
            charm: state[7] & 0x80 != 0,
            moon_frag: state[7] & 0x40 != 0,
            uni_horn: state[7] & 0x20 != 0,
            ring: state[7] & 0x10 != 0,
            sapphire: state[7] & 0x08 != 0,
            trt_fruit: state[7] & 0x04 != 0,
            fairy_lmp: state[7] & 0x02 != 0,
            spore: state[7] & 0x01 != 0,
            doll: state[8] & 0x80 != 0,
            y_fruit: state[8] & 0x40 != 0,
            ivy_seed: state[8] & 0x20 != 0,
            events: Events::from_bits(((state[8] as u16) << 8 | state[9] as u16) & 0x1fff).unwrap(),
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "| Feature        | Value    |")?;
        writeln!(f, "|----------------|----------|")?;
        writeln!(f, "| Experience     | {:<8} |", self.experience)?;
        writeln!(f, "| Level          | {:<8} |", self.level)?;
        writeln!(f, "| Gold           | {:<8} |", self.gold)?;
        writeln!(f, "|----------------|----------|")?;
        writeln!(f, "| Barley         | {:<8} |", self.barley)?;
        writeln!(f, "| Wheat          | {:<8} |", self.wheat)?;
        writeln!(f, "| Herb           | {:<8} |", self.herb)?;
        writeln!(f, "| Sword          | {:<8} |", self.sword)?;
        writeln!(f, "| Armor          | {:<8} |", self.armor)?;
        writeln!(f, "|----------------|----------|")?;
        writeln!(f, "| Grace (Magic)  | {:<8} |", self.grace)?;
        writeln!(f, "| Secret (Magic) | {:<8} |", self.secret)?;
        writeln!(f, "| Key M          | {:<8} |", self.key_m)?;
        writeln!(f, "| Key S          | {:<8} |", self.key_s)?;
        writeln!(f, "| Key C          | {:<8} |", self.key_c)?;
        writeln!(f, "| W Egg          | {:<8} |", self.w_egg)?;
        writeln!(f, "| B Egg          | {:<8} |", self.b_egg)?;
        writeln!(f, "| R Egg          | {:<8} |", self.r_egg)?;
        writeln!(f, "| Ruby           | {:<8} |", self.ruby)?;
        writeln!(f, "| Charm          | {:<8} |", self.charm)?;
        writeln!(f, "| MoonFrag       | {:<8} |", self.moon_frag)?;
        writeln!(f, "| Uni Horn       | {:<8} |", self.uni_horn)?;
        writeln!(f, "| Ring           | {:<8} |", self.ring)?;
        writeln!(f, "| Sapphire       | {:<8} |", self.sapphire)?;
        writeln!(f, "| TrtFruit       | {:<8} |", self.trt_fruit)?;
        writeln!(f, "| FairyLmp       | {:<8} |", self.fairy_lmp)?;
        writeln!(f, "| Spore          | {:<8} |", self.spore)?;
        writeln!(f, "| Doll           | {:<8} |", self.doll)?;
        writeln!(f, "| Y Fruit        | {:<8} |", self.y_fruit)?;
        writeln!(f, "| Ivy Seed       | {:<8} |", self.ivy_seed)?;
        writeln!(f, "|----------------+----------|")?;
        writeln!(f, "| Events                    |")?;
        writeln!(f, "|---------------------------|")?;
        write!(f, "{}", self.events)
    }
}

#[derive(Debug)]
#[repr(u8)]
enum Sword {
    Probite,
    Star3,
    Extra,
    Adage,
    Wish,
    Copper,
    Silver,
    Gold,
}

impl From<u8> for Sword {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Probite,
            1 => Self::Star3,
            2 => Self::Extra,
            3 => Self::Adage,
            4 => Self::Wish,
            5 => Self::Copper,
            6 => Self::Silver,
            7 => Self::Gold,
            _ => unreachable!(),
        }
    }
}

impl fmt::Display for Sword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Probite => "Probite",
            Self::Star3 => "3 Star",
            Self::Extra => "Extra",
            Self::Adage => "Adage",
            Self::Wish => "Wish",
            Self::Copper => "Copper",
            Self::Silver => "Silver",
            Self::Gold => "Gold",
        })
    }
}

#[derive(Debug)]
#[repr(u8)]
enum Armor {
    Copper,
    Silver,
    Gold,
    Platinum,
}

impl From<u8> for Armor {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Copper,
            1 => Self::Silver,
            2 => Self::Gold,
            3 => Self::Platinum,
            _ => unreachable!(),
        }
    }
}

impl fmt::Display for Armor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Copper => "Copper",
            Self::Silver => "Silver",
            Self::Gold => "Gold",
            Self::Platinum => "Platinum",
        })
    }
}

bitflags! {
    #[derive(Debug, Eq, PartialEq)]
    struct Events: u16 {
        const Mistress = 0b1_0000_0000_0000;
        const Unknown11 = 0b0_1000_0000_0000;
        const Unknown10 = 0b0_0100_0000_0000;
        const Unknown9 = 0b0_0010_0000_0000;
        const Unknown8 = 0b0_0001_0000_0000;
        const Unknown7 = 0b0_0000_1000_0000;
        const Unknown6 = 0b0_0000_0100_0000;
        const Unknown5 = 0b0_0000_0010_0000;
        const Unknown4 = 0b0_0000_0001_0000;
        const Unknown3 = 0b0_0000_0000_1000;
        const Unknown2 = 0b0_0000_0000_0100;
        const TreesMet = 0b0_0000_0000_0010;
        const Unknown0 = 0b0_0000_0000_0001;
    }
}

impl fmt::Display for Events {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.contains(Self::Mistress) {
            writeln!(f, "|   - Spoken to Mistress    |")?;
        }
        if self.contains(Self::Unknown11) {
            writeln!(f, "|   - Unknown (11)          |")?;
        }
        if self.contains(Self::Unknown10) {
            writeln!(f, "|   - Unknown (10)          |")?;
        }
        if self.contains(Self::Unknown9) {
            writeln!(f, "|   - Unknown (9)           |")?;
        }
        if self.contains(Self::Unknown8) {
            writeln!(f, "|   - Unknown (8)           |")?;
        }
        if self.contains(Self::Unknown7) {
            writeln!(f, "|   - Unknown (7)           |")?;
        }
        if self.contains(Self::Unknown6) {
            writeln!(f, "|   - Unknown (6)           |")?;
        }
        if self.contains(Self::Unknown5) {
            writeln!(f, "|   - Unknown (5)           |")?;
        }
        if self.contains(Self::Unknown4) {
            writeln!(f, "|   - Unknown (4)           |")?;
        }
        if self.contains(Self::Unknown3) {
            writeln!(f, "|   - Unknown (3)           |")?;
        }
        if self.contains(Self::Unknown2) {
            writeln!(f, "|   - Unknown (2)           |")?;
        }
        if self.contains(Self::TreesMet) {
            writeln!(f, "|   - Met the Trees         |")?;
        }
        if self.contains(Self::Unknown0) {
            writeln!(f, "|   - Unknown (0)           |")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use io::Cursor;

    fn get_password(cursor: Cursor<Vec<u8>>) -> String {
        let bytes = cursor.into_inner();
        str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .last()
            .unwrap()
            .strip_prefix("Password: ")
            .unwrap()
            .to_string()
    }

    fn get_state(cursor: Cursor<Vec<u8>>) -> String {
        let bytes = cursor.into_inner();
        str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .strip_prefix("State: ")
            .unwrap()
            .trim_end()
            .to_string()
    }

    #[test]
    fn test_round_trip() {
        let state = "00 00 00 00 00 00 00 00 00";

        let mut output = Cursor::new(Vec::new());
        encoder(&mut output, state, false).unwrap();
        let password = get_password(output);

        let mut output = Cursor::new(Vec::new());
        decoder(&mut output, &password, false).unwrap();
        let decoded = get_state(output);

        assert_eq!(decoded, state);
    }

    #[test]
    fn test_encoder() {
        let state = "00 0f ff ff e7 ff ff e0 00";

        let mut output = Cursor::new(Vec::new());
        encoder(&mut output, state, false).unwrap();
        let password = get_password(output);

        assert_eq!(password, "3KNC CΞRD MBNF 5LDT");
    }

    #[test]
    fn test_decoder() {
        let password = "3KNC CΞRD MBNF 5LDT";

        let mut output = Cursor::new(Vec::new());
        decoder(&mut output, password, false).unwrap();
        let state = get_state(output);

        assert_eq!(state, "00 0f ff ff e7 ff ff e0 00");
    }
}
