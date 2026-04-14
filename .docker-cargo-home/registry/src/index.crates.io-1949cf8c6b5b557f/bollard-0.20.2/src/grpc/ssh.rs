use bytes::{Buf, Bytes, BytesMut};

use super::error::GrpcSshError;
use tokio_util::codec::Decoder;

type MessageTypeId = u8;
// Ref: https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04#section-5.1
const SSH_AGENT_FAILURE: MessageTypeId = 5;
const SSH_AGENT_SUCCESS: MessageTypeId = 6;
const SSH_AGENTC_REQUEST_IDENTITIES: MessageTypeId = 11;
const SSH_AGENTC_SIGN_RESPONSE: MessageTypeId = 13;
const SSH_AGENTC_EXTENSION: MessageTypeId = 27;

const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

#[derive(Debug, Copy, Clone)]
enum SshAgentPacketDecoderState {
    WaitingHeader,
    WaitingPayload(u8, u32), // StreamType, Length
}

#[derive(Debug)]
pub(crate) struct SshAgentPacketDecoder {
    state: SshAgentPacketDecoderState,
}

impl SshAgentPacketDecoder {
    #[inline]
    pub(crate) fn new() -> SshAgentPacketDecoder {
        Self {
            state: SshAgentPacketDecoderState::WaitingHeader,
        }
    }
}

impl Decoder for SshAgentPacketDecoder {
    type Item = Bytes;
    type Error = GrpcSshError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match self.state {
                SshAgentPacketDecoderState::WaitingHeader => {
                    if src.len() < 5 {
                        return Ok(None);
                    }

                    let mut header = &src[0..5];
                    let len = header.get_u32(); // big-endian

                    if len > MAX_MESSAGE_SIZE {
                        return Err(GrpcSshError::InvalidMessage(format!(
                            "Refusing to read message with size larger than {}",
                            MAX_MESSAGE_SIZE,
                        )));
                    }
                    let message_type = header.get_u8();
                    self.state = SshAgentPacketDecoderState::WaitingPayload(message_type, len);
                }
                SshAgentPacketDecoderState::WaitingPayload(message_type, length) => {
                    log::trace!("payload: {}, {}", message_type, length);
                    if u32::try_from(src.len())? < length {
                        return Ok(None);
                    } else {
                        let message = src.split_to(src.len()).freeze();

                        match message_type {
                            SSH_AGENTC_REQUEST_IDENTITIES | SSH_AGENTC_SIGN_RESPONSE => {
                                self.state = SshAgentPacketDecoderState::WaitingHeader;
                                return Ok(Some(message));
                            }

                            SSH_AGENTC_EXTENSION => {
                                // no-op the ssh agent extension message type

                                log::warn!("sshforward extension not supported");
                                src.advance(src.len());
                                self.state = SshAgentPacketDecoderState::WaitingHeader;

                                return Ok(Some(Bytes::from_static(b"\0\0\0\x01\x06")));
                            }

                            e => {
                                log::error!(
                                    "sshforward unsupported message type: {}",
                                    &message_type
                                );
                                self.state = SshAgentPacketDecoderState::WaitingHeader;
                                return Err(GrpcSshError::InvalidMessageType(e));
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    use crate::grpc::ssh::{SSH_AGENTC_EXTENSION, SSH_AGENTC_REQUEST_IDENTITIES};

    use super::SshAgentPacketDecoder;

    #[test]
    fn test_sshforward_message_identities_answer() {
        let mut buf = BytesMut::from(&b"\0\0\0\x05\x0c\0\0\0\0"[..]);
        let mut codec: SshAgentPacketDecoder = SshAgentPacketDecoder::new();

        assert!(codec.decode(&mut buf).is_err());
    }

    #[test]
    fn test_sshforward_message_unknown() {
        let mut buf = BytesMut::from(&b"\0\0\0\x01\xff"[..]);
        let mut codec: SshAgentPacketDecoder = SshAgentPacketDecoder::new();

        assert!(codec.decode(&mut buf).is_err());
    }

    #[test]
    fn test_sshforward_request_identities() {
        let mut buf = BytesMut::from_iter(vec![0_u8, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES]);
        let mut codec: SshAgentPacketDecoder = SshAgentPacketDecoder::new();

        assert_eq!(
            codec.decode(&mut buf).unwrap(),
            Some(bytes::Bytes::from_static(b"\0\0\0\x01\x0b".as_slice()))
        );
    }

    #[test]
    fn test_sshforward_extension() {
        let mut buf = BytesMut::from_iter(vec![0_u8, 0, 0, 1, SSH_AGENTC_EXTENSION]);
        let mut codec: SshAgentPacketDecoder = SshAgentPacketDecoder::new();

        assert_eq!(
            codec.decode(&mut buf).unwrap(),
            Some(bytes::Bytes::from_static(b"\0\0\0\x01\x06".as_slice()))
        );
    }

    #[test]
    fn test_sshforward_overly_long_message_length() {
        let mut buf = BytesMut::from(&b"\x01\0\0\x01\xff"[..]);
        let mut codec: SshAgentPacketDecoder = SshAgentPacketDecoder::new();

        assert!(codec.decode(&mut buf).is_err());
    }
}
