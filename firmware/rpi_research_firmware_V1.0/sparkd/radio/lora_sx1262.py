"""
SPARK LoRa SX1262 Radio Driver

Driver for Waveshare SX1262 LoRa HAT on Raspberry Pi.

Hardware Requirements:
- Raspberry Pi 5 (or compatible)
- Waveshare SX1262 LoRa HAT
- SPI enabled (raspi-config)

Connections (Waveshare HAT):
- SPI0: MOSI=GPIO10, MISO=GPIO9, SCLK=GPIO11, CS=GPIO8
- RESET: GPIO18
- BUSY: GPIO20
- DIO1: GPIO16

SECURITY NOTES:
- Radio transmissions are unencrypted at this layer
- All encryption handled by upper layers
- Physical layer provides no authentication

Dependencies:
- python3-spidev (apt install python3-spidev)
- python3-rpi.gpio or lgpio for Raspberry Pi 5
"""

import time
import struct
import threading
from typing import Optional
from enum import IntEnum

from .base import (
    BaseRadio,
    RadioConfig,
    RadioState,
    RadioError,
    RadioPacket,
)

# Try to import GPIO libraries
# Raspberry Pi 5 uses lgpio instead of RPi.GPIO
try:
    import lgpio
    GPIO_LIB = "lgpio"
except ImportError:
    try:
        import RPi.GPIO as GPIO
        GPIO_LIB = "RPi.GPIO"
    except ImportError:
        GPIO_LIB = None

try:
    import spidev
    HAS_SPI = True
except ImportError:
    HAS_SPI = False


# SX1262 Register addresses
class SX1262Reg(IntEnum):
    """SX1262 register addresses."""
    # Operating modes
    SET_SLEEP = 0x84
    SET_STANDBY = 0x80
    SET_FS = 0xC1
    SET_TX = 0x83
    SET_RX = 0x82
    SET_RX_DUTY_CYCLE = 0x94
    SET_CAD = 0xC5
    SET_TX_CONTINUOUS = 0xD1
    SET_TX_INFINITE_PREAMBLE = 0xD2
    
    # Register access
    WRITE_REGISTER = 0x0D
    READ_REGISTER = 0x1D
    WRITE_BUFFER = 0x0E
    READ_BUFFER = 0x1E
    
    # DIO and IRQ
    SET_DIO_IRQ_PARAMS = 0x08
    GET_IRQ_STATUS = 0x12
    CLR_IRQ_STATUS = 0x02
    SET_DIO2_AS_RF_SWITCH = 0x9D
    SET_DIO3_AS_TCXO = 0x97
    
    # RF, Modulation, Packet
    SET_RF_FREQUENCY = 0x86
    SET_PACKET_TYPE = 0x8A
    GET_PACKET_TYPE = 0x11
    SET_TX_PARAMS = 0x8E
    SET_MODULATION_PARAMS = 0x8B
    SET_PACKET_PARAMS = 0x8C
    SET_CAD_PARAMS = 0x88
    SET_BUFFER_BASE_ADDR = 0x8F
    SET_LORA_SYMB_TIMEOUT = 0xA0
    
    # Status
    GET_STATUS = 0xC0
    GET_RX_BUFFER_STATUS = 0x13
    GET_PACKET_STATUS = 0x14
    GET_RSSI_INST = 0x15
    GET_STATS = 0x10
    RESET_STATS = 0x00
    GET_DEVICE_ERRORS = 0x17
    CLR_DEVICE_ERRORS = 0x07


# SX1262 IRQ flags
class SX1262IRQ(IntEnum):
    """SX1262 interrupt flags."""
    TX_DONE = 0x0001
    RX_DONE = 0x0002
    PREAMBLE_DETECTED = 0x0004
    SYNC_WORD_VALID = 0x0008
    HEADER_VALID = 0x0010
    HEADER_ERR = 0x0020
    CRC_ERR = 0x0040
    CAD_DONE = 0x0080
    CAD_DETECTED = 0x0100
    TIMEOUT = 0x0200
    ALL = 0x03FF


# GPIO pin assignments for Waveshare HAT
class WavesharePins:
    """GPIO pin assignments for Waveshare SX1262 HAT."""
    RESET = 18
    BUSY = 20
    DIO1 = 16
    NSS = 21  # Chip select (active low) - Waveshare uses GPIO21, not SPI HW CS


class LoRaSX1262Radio(BaseRadio):
    """
    Driver for Waveshare SX1262 LoRa HAT.
    
    Implements the BaseRadio interface for SX1262-based LoRa modules.
    
    Usage:
        radio = LoRaSX1262Radio()
        config = RadioConfig(
            frequency=915000000,  # 915 MHz
            tx_power=17,          # 17 dBm
            spreading_factor=9,
            bandwidth=125000,
        )
        radio.configure(config)
        radio.start_receive()
        
        # Receive
        packet = radio.receive(timeout_ms=5000)
        
        # Transmit
        radio.transmit(b"Hello LoRa!")
    """
    
    def __init__(
        self,
        name: str = "sx1262",
        spi_bus: int = 0,
        spi_device: int = 0,
        reset_pin: int = WavesharePins.RESET,
        busy_pin: int = WavesharePins.BUSY,
        dio1_pin: int = WavesharePins.DIO1,
        nss_pin: int = WavesharePins.NSS,
    ):
        """
        Initialize SX1262 radio driver.
        
        Args:
            name: Radio instance name
            spi_bus: SPI bus number (0 or 1)
            spi_device: SPI device/CS number (0 or 1)
            reset_pin: GPIO pin for radio reset
            busy_pin: GPIO pin for busy indicator
            dio1_pin: GPIO pin for DIO1 interrupt
            nss_pin: GPIO pin for SPI chip select (NSS)
        """
        super().__init__(name)
        
        # Check dependencies
        if not HAS_SPI:
            raise RadioError("spidev not available - install python3-spidev")
        if GPIO_LIB is None:
            raise RadioError("No GPIO library available - install lgpio or RPi.GPIO")
        
        # Pin assignments
        self._reset_pin = reset_pin
        self._busy_pin = busy_pin
        self._dio1_pin = dio1_pin
        self._nss_pin = nss_pin
        
        # SPI configuration
        self._spi_bus = spi_bus
        self._spi_device = spi_device
        self._spi: Optional[spidev.SpiDev] = None
        
        # GPIO handle for lgpio
        self._gpio_handle = None
        
        # Thread safety lock for radio operations
        self._lock = threading.Lock()
        
        # Initialize hardware
        self._init_gpio()
        self._init_spi()
    
    def _init_gpio(self) -> None:
        """Initialize GPIO pins."""
        if GPIO_LIB == "lgpio":
            self._gpio_handle = lgpio.gpiochip_open(0)
            
            # Configure pins
            lgpio.gpio_claim_output(self._gpio_handle, self._reset_pin, 1)
            lgpio.gpio_claim_input(self._gpio_handle, self._busy_pin)
            lgpio.gpio_claim_input(self._gpio_handle, self._dio1_pin)
            # NSS (chip select) - active low, start deselected (high)
            lgpio.gpio_claim_output(self._gpio_handle, self._nss_pin, 1)
        else:
            GPIO.setmode(GPIO.BCM)
            GPIO.setwarnings(False)
            
            GPIO.setup(self._reset_pin, GPIO.OUT, initial=GPIO.HIGH)
            GPIO.setup(self._busy_pin, GPIO.IN)
            GPIO.setup(self._dio1_pin, GPIO.IN)
            # NSS (chip select) - active low, start deselected (high)
            GPIO.setup(self._nss_pin, GPIO.OUT, initial=GPIO.HIGH)
    
    def _init_spi(self) -> None:
        """Initialize SPI interface."""
        self._spi = spidev.SpiDev()
        self._spi.open(self._spi_bus, self._spi_device)
        self._spi.max_speed_hz = 2000000  # 2 MHz
        self._spi.mode = 0
        # Disable hardware CS; we use GPIO21 (NSS) manually
        try:
            self._spi.no_cs = True
        except (IOError, OSError):
            pass  # Kernel may not support SPI_NO_CS; GPIO21 still works
    
    def _gpio_write(self, pin: int, value: int) -> None:
        """Write to a GPIO pin."""
        if GPIO_LIB == "lgpio":
            lgpio.gpio_write(self._gpio_handle, pin, value)
        else:
            GPIO.output(pin, value)
    
    def _gpio_read(self, pin: int) -> int:
        """Read from a GPIO pin."""
        if GPIO_LIB == "lgpio":
            return lgpio.gpio_read(self._gpio_handle, pin)
        else:
            return GPIO.input(pin)
    
    def _cs_select(self) -> None:
        """Assert chip select (NSS low)."""
        self._gpio_write(self._nss_pin, 0)
    
    def _cs_deselect(self) -> None:
        """Deassert chip select (NSS high)."""
        self._gpio_write(self._nss_pin, 1)
    
    def _wait_busy(self, timeout_ms: int = 1000) -> None:
        """Wait for BUSY pin to go low."""
        start = time.time()
        while self._gpio_read(self._busy_pin):
            if (time.time() - start) * 1000 > timeout_ms:
                raise RadioError("Timeout waiting for BUSY")
            time.sleep(0.001)
    
    def _spi_command(self, cmd: int, data: bytes = b"") -> bytes:
        """Send command to radio via SPI."""
        self._wait_busy()
        
        # Build command buffer
        tx_buf = bytes([cmd]) + data
        
        # Transfer with manual CS control (Waveshare HAT uses GPIO21 for NSS)
        self._cs_select()
        rx_buf = self._spi.xfer2(list(tx_buf))
        self._cs_deselect()
        
        return bytes(rx_buf[1:])  # Skip status byte
    
    def _spi_read_command(self, cmd: int, length: int) -> bytes:
        """Read data from radio via SPI."""
        self._wait_busy()
        
        # Send command followed by NOP bytes to clock out response
        tx_buf = [cmd, 0x00] + [0x00] * length
        
        self._cs_select()
        rx_buf = self._spi.xfer2(tx_buf)
        self._cs_deselect()
        
        return bytes(rx_buf[2:])  # Skip command echo and status
    
    def _hardware_reset(self) -> None:
        """Perform hardware reset of the radio."""
        self._gpio_write(self._reset_pin, 0)
        time.sleep(0.01)  # 10ms low
        self._gpio_write(self._reset_pin, 1)
        time.sleep(0.01)  # 10ms settling
        self._wait_busy()
    
    def _set_standby(self, mode: int = 0) -> None:
        """Put radio in standby mode (0=RC, 1=XOSC)."""
        self._spi_command(SX1262Reg.SET_STANDBY, bytes([mode]))
    
    def _set_packet_type(self, packet_type: int = 1) -> None:
        """Set packet type (0=GFSK, 1=LoRa)."""
        self._spi_command(SX1262Reg.SET_PACKET_TYPE, bytes([packet_type]))
    
    def _set_frequency(self, freq_hz: int) -> None:
        """Set RF frequency in Hz."""
        # SX1262 frequency = freq_hz * 2^25 / 32MHz
        freq_reg = int(freq_hz * (2**25) / 32000000)
        data = struct.pack(">I", freq_reg)
        self._spi_command(SX1262Reg.SET_RF_FREQUENCY, data)
    
    def _set_tx_params(self, power: int, ramp_time: int = 0x04) -> None:
        """Set TX power and ramp time."""
        # Power: -9 to +22 dBm
        # Ramp time: 0x04 = 200us
        self._spi_command(SX1262Reg.SET_TX_PARAMS, bytes([power, ramp_time]))
    
    def _set_modulation_params(self, sf: int, bw: int, cr: int) -> None:
        """Set LoRa modulation parameters."""
        # Bandwidth: 0=7.8kHz, 4=31.25kHz, 5=62.5kHz, 6=125kHz, 7=250kHz, 8=500kHz
        bw_map = {
            7800: 0x00,
            15600: 0x01,
            31250: 0x04,
            62500: 0x05,
            125000: 0x06,
            250000: 0x07,
            500000: 0x08,
        }
        bw_reg = bw_map.get(bw, 0x06)
        
        # Coding rate: 1=4/5, 2=4/6, 3=4/7, 4=4/8
        cr_reg = cr - 4  # Convert 5-8 to 1-4
        
        # Low data rate optimize (required for SF11/12 with 125kHz)
        ldro = 1 if (sf >= 11 and bw <= 125000) else 0
        
        self._spi_command(
            SX1262Reg.SET_MODULATION_PARAMS,
            bytes([sf, bw_reg, cr_reg, ldro])
        )
    
    def _set_packet_params(
        self,
        preamble: int,
        header_type: int = 0,
        payload_len: int = 255,
        crc: bool = True,
        invert_iq: bool = False,
    ) -> None:
        """Set LoRa packet parameters."""
        self._spi_command(
            SX1262Reg.SET_PACKET_PARAMS,
            struct.pack(
                ">HBBBBB",
                preamble,
                header_type,  # 0=variable, 1=fixed
                payload_len,
                1 if crc else 0,
                1 if invert_iq else 0,
                0,  # Reserved
            )[:6]
        )
    
    def _set_buffer_base(self, tx_base: int = 0, rx_base: int = 0) -> None:
        """Set TX and RX buffer base addresses."""
        self._spi_command(SX1262Reg.SET_BUFFER_BASE_ADDR, bytes([tx_base, rx_base]))
    
    def _set_dio_irq_params(self, irq_mask: int, dio1_mask: int) -> None:
        """Configure IRQ and DIO1 mapping."""
        self._spi_command(
            SX1262Reg.SET_DIO_IRQ_PARAMS,
            struct.pack(">HHHH", irq_mask, dio1_mask, 0, 0)
        )
    
    def _get_irq_status(self) -> int:
        """Get current IRQ status."""
        data = self._spi_read_command(SX1262Reg.GET_IRQ_STATUS, 2)
        return struct.unpack(">H", data)[0]
    
    def _clear_irq_status(self, mask: int = 0xFFFF) -> None:
        """Clear IRQ flags."""
        self._spi_command(SX1262Reg.CLR_IRQ_STATUS, struct.pack(">H", mask))
    
    def _write_buffer(self, offset: int, data: bytes) -> None:
        """Write data to radio buffer."""
        self._spi_command(SX1262Reg.WRITE_BUFFER, bytes([offset]) + data)
    
    def _read_buffer(self, offset: int, length: int) -> bytes:
        """Read data from radio buffer."""
        self._wait_busy()
        tx_buf = [SX1262Reg.READ_BUFFER, offset, 0x00] + [0x00] * length
        self._cs_select()
        rx_buf = self._spi.xfer2(tx_buf)
        self._cs_deselect()
        return bytes(rx_buf[3:])
    
    def _get_rx_buffer_status(self) -> tuple:
        """Get RX buffer status (payload length, start offset)."""
        data = self._spi_read_command(SX1262Reg.GET_RX_BUFFER_STATUS, 2)
        return data[0], data[1]  # length, offset
    
    def _get_packet_status(self) -> tuple:
        """Get packet status (RSSI, SNR)."""
        data = self._spi_read_command(SX1262Reg.GET_PACKET_STATUS, 3)
        rssi = -data[0] // 2  # RSSI in dBm
        snr = data[1] / 4     # SNR in dB (signed)
        if snr > 127:
            snr -= 256
        return rssi, snr
    
    def _write_register(self, addr: int, data: bytes) -> None:
        """Write to SX1262 register(s)."""
        addr_bytes = struct.pack(">H", addr)
        self._spi_command(SX1262Reg.WRITE_REGISTER, addr_bytes + data)

    def _set_sync_word(self, sync_word: int) -> None:
        """Set LoRa sync word.
        
        Converts standard LoRa sync word (e.g. 0x12 private, 0x34 public)
        to SX1262 register format and writes to registers 0x0740-0x0741.
        """
        reg_hi = (sync_word & 0xF0) | 0x04
        reg_lo = ((sync_word & 0x0F) << 4) | 0x04
        self._write_register(0x0740, bytes([reg_hi, reg_lo]))

    def _set_pa_config(self, tx_power: int) -> None:
        """Configure the SX1262 high-power PA.
        
        Must be called before SET_TX_PARAMS. Sets the PA duty cycle,
        HP max, device selection, and over-current protection for the
        SX1262's high-power amplifier.
        
        Args:
            tx_power: Desired TX power in dBm (-9 to +22)
        """
        # SX1262 HP PA configuration
        # paDutyCycle and hpMax control the PA output capability
        if tx_power > 20:
            pa_duty_cycle = 0x04
            hp_max = 0x07  # +22 dBm capable
        elif tx_power > 17:
            pa_duty_cycle = 0x03
            hp_max = 0x05  # +20 dBm capable
        elif tx_power > 14:
            pa_duty_cycle = 0x02
            hp_max = 0x03  # +17 dBm capable
        else:
            pa_duty_cycle = 0x02
            hp_max = 0x02  # +14 dBm capable
        
        # SET_PA_CONFIG: paDutyCycle, hpMax, deviceSel=0x00 (SX1262), paLut=0x01
        self._spi_command(0x95, bytes([pa_duty_cycle, hp_max, 0x00, 0x01]))
        
        # Set over-current protection for HP PA (140 mA)
        self._write_register(0x08E7, bytes([0x38]))

    def configure(self, config: RadioConfig) -> None:
        """Configure the SX1262 radio."""
        self._validate_config(config)
        self._config = config
        
        # Hardware reset
        self._hardware_reset()
        
        # Enter standby
        self._set_standby()
        
        # Set regulator mode to DC-DC (Waveshare HAT uses DC-DC regulator)
        self._spi_command(0x96, bytes([0x01]))
        
        # Configure DIO2 as RF switch control
        self._spi_command(SX1262Reg.SET_DIO2_AS_RF_SWITCH, bytes([0x01]))
        
        # Set LoRa mode
        self._set_packet_type(1)
        
        # Configure PA for SX1262 high-power amplifier (must precede SET_TX_PARAMS)
        self._set_pa_config(config.tx_power)
        
        # Set frequency
        self._set_frequency(config.frequency)
        
        # Set TX power
        self._set_tx_params(config.tx_power)
        
        # Set modulation parameters
        self._set_modulation_params(
            config.spreading_factor,
            config.bandwidth,
            config.coding_rate,
        )
        
        # Set packet parameters
        self._set_packet_params(
            config.preamble_length,
            header_type=0,  # Variable length
            payload_len=config.max_packet_size,
            crc=config.crc_enabled,
        )
        
        # Set LoRa sync word
        self._set_sync_word(config.sync_word)
        
        # Set buffer base addresses
        self._set_buffer_base(0, 0)
        
        # Configure IRQ for TX/RX done
        self._set_dio_irq_params(
            SX1262IRQ.TX_DONE | SX1262IRQ.RX_DONE | SX1262IRQ.TIMEOUT | SX1262IRQ.CRC_ERR,
            SX1262IRQ.TX_DONE | SX1262IRQ.RX_DONE | SX1262IRQ.TIMEOUT,
        )
        
        self._state = RadioState.IDLE
    
    def transmit(self, data: bytes) -> bool:
        """Transmit a packet (thread-safe)."""
        self._validate_packet(data)
        
        if self._state == RadioState.SLEEPING:
            raise RadioError("Radio is sleeping")
        
        with self._lock:
            # Remember if we need to restore receive mode after TX
            was_receiving = (self._state == RadioState.RECEIVING)
            
            try:
                # Enter standby
                self._set_standby()
                self._state = RadioState.TRANSMITTING
                
                # Clear IRQ
                self._clear_irq_status()
                
                # Write data to buffer
                self._write_buffer(0, data)
                
                # Set packet length
                self._set_packet_params(
                    self._config.preamble_length,
                    header_type=0,
                    payload_len=len(data),
                    crc=self._config.crc_enabled,
                )
                
                # Start transmission (timeout=0 for no timeout)
                self._spi_command(SX1262Reg.SET_TX, bytes([0x00, 0x00, 0x00]))
                
                # Wait for TX done
                start = time.time()
                while True:
                    irq = self._get_irq_status()
                    if irq & SX1262IRQ.TX_DONE:
                        break
                    if time.time() - start > 10:  # 10 second timeout
                        self._tx_errors += 1
                        raise RadioError("TX timeout")
                    time.sleep(0.001)
                
                # Clear IRQ
                self._clear_irq_status()
                
                self._packets_sent += 1
                return True
                
            finally:
                # Always restore receive mode or idle, even on error
                if was_receiving:
                    try:
                        self._set_standby()
                        self._clear_irq_status()
                        # Restore packet params for RX (max payload length)
                        self._set_packet_params(
                            self._config.preamble_length,
                            header_type=0,
                            payload_len=self._config.max_packet_size,
                            crc=self._config.crc_enabled,
                        )
                        self._spi_command(SX1262Reg.SET_RX, bytes([0xFF, 0xFF, 0xFF]))
                        self._state = RadioState.RECEIVING
                    except Exception:
                        self._state = RadioState.ERROR
                else:
                    self._state = RadioState.IDLE
    
    def receive(self, timeout_ms: int = 1000) -> Optional[RadioPacket]:
        """Receive a packet (thread-safe)."""
        if self._state == RadioState.SLEEPING:
            raise RadioError("Radio is sleeping")
        
        if self._state not in (RadioState.RECEIVING, RadioState.TRANSMITTING):
            raise RadioError("Radio not in receive mode")
        
        # If another thread is transmitting, wait briefly and return None
        if not self._lock.acquire(timeout=timeout_ms / 1000.0):
            return None
        
        try:
            if self._state != RadioState.RECEIVING:
                return None
            
            # Wait for RX done or timeout
            start = time.time()
            while True:
                irq = self._get_irq_status()
                
                if irq & SX1262IRQ.RX_DONE:
                    # Check for CRC error
                    if irq & SX1262IRQ.CRC_ERR:
                        self._clear_irq_status()
                        self._rx_errors += 1
                        continue  # Keep waiting
                    
                    # Read packet
                    payload_len, offset = self._get_rx_buffer_status()
                    data = self._read_buffer(offset, payload_len)
                    
                    # Get RSSI/SNR
                    rssi, snr = self._get_packet_status()
                    
                    # Clear IRQ
                    self._clear_irq_status()
                    
                    packet = RadioPacket(
                        data=data,
                        timestamp=time.time(),
                        rssi=rssi,
                        snr=snr,
                    )
                    
                    self._packets_received += 1
                    
                    # Call callback if set
                    if self._rx_callback:
                        self._rx_callback(packet)
                    
                    return packet
                
                if irq & SX1262IRQ.TIMEOUT:
                    self._clear_irq_status()
                    return None
                
                elapsed = (time.time() - start) * 1000
                if timeout_ms > 0 and elapsed > timeout_ms:
                    return None
                
                time.sleep(0.001)
        finally:
            self._lock.release()
    
    def start_receive(self) -> None:
        """Start continuous receive mode."""
        if self._state == RadioState.UNINITIALIZED:
            raise RadioError("Radio not configured")
        
        with self._lock:
            # Enter standby first
            self._set_standby()
            
            # Clear IRQ
            self._clear_irq_status()
            
            # Start RX (continuous mode: 0xFFFFFF timeout)
            self._spi_command(SX1262Reg.SET_RX, bytes([0xFF, 0xFF, 0xFF]))
            
            self._state = RadioState.RECEIVING
    
    def stop_receive(self) -> None:
        """Stop receive mode."""
        self._set_standby()
        self._state = RadioState.IDLE
    
    def sleep(self) -> None:
        """Put radio into sleep mode."""
        self.stop_receive()
        self._spi_command(SX1262Reg.SET_SLEEP, bytes([0x04]))  # Warm start
        self._state = RadioState.SLEEPING
    
    def reset(self) -> None:
        """Reset radio."""
        self._hardware_reset()
        self._state = RadioState.UNINITIALIZED
    
    def __del__(self):
        """Cleanup resources."""
        try:
            if self._spi:
                self._spi.close()
            if GPIO_LIB == "lgpio" and self._gpio_handle is not None:
                lgpio.gpiochip_close(self._gpio_handle)
        except Exception:
            pass
