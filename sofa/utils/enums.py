from enum import Enum


class ARMChairSessionMode(Enum):
    AUTO = "auto"
    USER = "user"
    USER_CSV = "user-csv"
    USER_RAW = "user-raw"


class TargetResponse(Enum):
    """
    Enum representing the response status from the target device during communication.

    Attributes:
        OK (str): Indicates that the operation was successful.
        ERR (str): Indicates that an error occurred during the operation.
    """

    OK = "OK"
    ERR = "ERR"


class AesQilingStatus(Enum):
    """
    Enum representing the various stages of AES command execution in Qiling.

    Attributes:
        INIT (int): Indicates that the commands are being registered.
        WAIT_CMD (int): Indicates that Qiling is waiting for commands.
        KEY_SET (int): Indicates that the AES key has been successfully set.
        IV_SET (int): Indicates that the initialization vector (IV) has been set (optional).
        ENC_DONE (int): Indicates that the AES encryption process is complete.
    """

    INIT = 0
    WAIT_CMD = 1
    KEY_SET = 2
    IV_SET = 3
    ENC_DONE = 4


class AsconQilingStatus(Enum):
    """
    Enum representing the initialization stage for Ascon command execution in Qiling.

    Attributes:
        INIT (int): Indicates that the commands are being registered.
        WAIT_CMD (int): Indicates that Qiling is waiting for commands.
        KEY_SET (int): Indicates that the ASCON key has been successfully set.
        NONCE_SET (int): Indicates that the nonce has been set.
        AD_SET (int): Indicates that the associated data has been set.
        ENC_DONE (int): Indicates that the ASCON encryption process is complete.
    """

    INIT = 0
    WAIT_CMD = 1
    KEY_SET = 2
    NONCE_SET = 3
    AD_SET = 4
    ENC_DONE = 5


class KeccakQilingStatus(Enum):
    """
    Enum representing the initialization stage for Keccak command execution in Qiling.

    Attributes:
        INIT (int): Indicates that the commands are being registered.
    """

    INIT = 0
    WAIT_CMD = 1
    HASH_DONE = 2
