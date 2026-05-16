import re
import time
import math
import hashlib


LOG_FILE = "lms-stage-access.log"

IP_PATTERN = re.compile(r'"remote_addr"\s*:\s*"([^"]+)"')


def iter_ips(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            match = IP_PATTERN.search(line)

            if match:
                ip = match.group(1).strip()

                if ip:
                    yield ip


def exact_unique_count(file_path):
    unique_ips = set()

    for ip in iter_ips(file_path):
        unique_ips.add(ip)

#    print(unique_ips)  # для перевірки унікальних IP-адрес
    return len(unique_ips)


class HyperLogLog:
    def __init__(self, p=14):
        """
        p — кількість бітів для індексу регістра.
        m = 2^p — кількість регістрів.
        p=14 дає 16384 регістри і приблизну похибку ~0.8%.
        """
        if not 4 <= p <= 16:
            raise ValueError("p має бути в межах від 4 до 16")

        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m

        if self.m == 16:
            self.alpha = 0.673
        elif self.m == 32:
            self.alpha = 0.697
        elif self.m == 64:
            self.alpha = 0.709
        else:
            self.alpha = 0.7213 / (1 + 1.079 / self.m)

    @staticmethod
    def _hash64(value):
        digest = hashlib.blake2b(
            str(value).encode("utf-8"),
            digest_size=8
        ).digest()

        return int.from_bytes(digest, byteorder="big", signed=False)

    @staticmethod
    def _leading_zeros(x, bits):
        """
        Рахує кількість нулів зліва у двійковому представленні.
        """
        if x == 0:
            return bits

        return bits - x.bit_length()

    def add(self, value):
        """
        Додає елемент у HyperLogLog.
        """
        x = self._hash64(value)

        register_index = x & (self.m - 1)
        remaining_bits = x >> self.p

        rank = self._leading_zeros(remaining_bits, 64 - self.p) + 1

        self.registers[register_index] = max(
            self.registers[register_index],
            rank
        )

    def count(self):
        indicator = sum(2.0 ** (-register) for register in self.registers)
        raw_estimate = self.alpha * (self.m ** 2) / indicator
        zero_registers = self.registers.count(0)

        # Корекція для малих кардинальностей
        if raw_estimate <= 2.5 * self.m and zero_registers > 0:
            return self.m * math.log(self.m / zero_registers)

        return raw_estimate


def hll_unique_count(file_path, p=14):
    hll = HyperLogLog(p=p)

    for ip in iter_ips(file_path):
        hll.add(ip)

    return round(hll.count())


def measure_time(func, *args):
    start_time = time.perf_counter()
    result = func(*args)
    end_time = time.perf_counter()

    return result, end_time - start_time


def main():
    exact_count, exact_time = measure_time(exact_unique_count, LOG_FILE)
    hll_count, hll_time = measure_time(hll_unique_count, LOG_FILE)

    error_percent = abs(hll_count - exact_count) / exact_count * 100

    print("Результати порівняння:")
    print("-" * 70)
    print(f"{'Метод':<30} {'Унікальні IP':<20} {'Час, сек':<15}")
    print("-" * 70)
    print(f"{'Точний підрахунок set':<30} {exact_count:<20} {exact_time:<15.6f}")
    print(f"{'HyperLogLog':<30} {hll_count:<20} {hll_time:<15.6f}")
    print("-" * 70)
    print(f"Похибка HyperLogLog: {error_percent:.2f}%")

    if hll_time > 0:
        speed_ratio = exact_time / hll_time
        print(f"Співвідношення часу set / HLL: {speed_ratio:.2f}x")


if __name__ == "__main__":
    main()


# За результатами тестування точний підрахунок за допомогою set показав кращий час виконання, ніж HyperLogLog.
# Це пояснюється невеликою кількістю унікальних IP-адрес у лог-файлі. 
# HyperLogLog має додаткові обчислювальні витрати на хешування та оновлення регістрів, 
# тому на малих наборах даних може бути повільнішим.

# Водночас HyperLogLog дав таку саму оцінку кількості унікальних IP-адрес, як і точний метод, 
# тобто похибка склала 0.00%. Основна перевага HyperLogLog проявляється на великих наборах даних, 
# де важливо зменшити використання памʼяті при наближеному підрахунку унікальних елементів.