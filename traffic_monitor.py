import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from collections import defaultdict
import warnings
import logging
import requests  # Добавлено для Telegram

warnings.filterwarnings('ignore')

class NetworkTrafficAnalyzer:
    """
    Класс для анализа сетевого трафика предприятия
    """
    def __init__(self, company_name="ТехноПрофи"):
        """
        Инициализация анализатора трафика
        """
        self.company_name = company_name
        self.traffic_log = []
        self.alerts = []
        self.policy_violations = []
        
        # Политики безопасности предприятия
        self.security_policies = {
            'max_daily_external_traffic': 10737418240,  # 10 ГБ
            'blocked_ports': [21, 23, 135, 139, 445],  # Опасные порты
            'suspicious_ips': ['192.168.1.100', '10.0.0.15'],
            'work_hours': {'start': 9, 'end': 18},  # Рабочие часы
            'allowed_protocols': ['HTTP', 'HTTPS', 'SSH', 'SMTP', 'DNS']
        }
        
        # Шаблоны аномалий
        self.anomaly_patterns = {
            'port_scan': {'threshold': 100, 'window_minutes': 5},
            'ddos_attack': {'threshold': 1000, 'window_minutes': 1}, # 1000 пакетов в минуту
            'data_exfiltration': {'threshold': 524288000, 'window_minutes': 60}  # 500 МБ
        }
        
        # ЗАДАНИЕ 1: Настройка журнала аудита
        logging.basicConfig(filename='security_audit.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')
        logging.info("Система мониторинга запущена.")
        
        print(f"Инициализирован анализатор трафика для: {company_name}")
        print(f"Время запуска: {datetime.now()}")

    # ЗАДАНИЕ 1: Отправка оповещений в Telegram
    def send_telegram_alert(self, message):
        """
        Отправка оповещения в Telegram (имитация)
        """
        print(f" [TELEGRAM ALERT]: {message}")
        logging.warning(f"Отправлено оповещение в Telegram: {message}")
        
        # Для реальной отправки раскомментируйте код ниже и укажите свои данные:
        # TOKEN = "ВАШ_ТОКЕН_БОТА"
        # CHAT_ID = "ВАШ_CHAT_ID"
        # try:
        #     requests.post(f"https://api.telegram.org/bot{TOKEN}/sendMessage", 
        #                   data={"chat_id": CHAT_ID, "text": message}, timeout=5)
        # except Exception as e:
        #     logging.error(f"Ошибка отправки в Telegram: {e}")

    def simulate_traffic_data(self, hours=24, users=50):
        """
        Генерация имитационных данных трафика
        """
        print(f"\nГенерация имитационных данных за {hours} часов...")
        np.random.seed(42)
        
        timestamps, sources, destinations = [], [], []
        protocols, ports, sizes, departments = [], [], [], []
        
        departments_list = ['Финансы', 'IT', 'Маркетинг', 'HR', 'Продажи', 'Руководство']
        protocols_list = ['HTTP', 'HTTPS', 'SSH', 'SMTP', 'FTP', 'DNS', 'RDP'] # Исправлена запятая
        
        start_time = datetime.now() - timedelta(hours=hours)
        
        for i in range(10000):
            # Временная метка
            time_offset = timedelta(seconds=np.random.randint(0, hours * 3600))
            timestamps.append(start_time + time_offset)
            
            # Источник
            user_id = np.random.randint(1, users + 1)
            dept = np.random.choice(departments_list, p=[0.1, 0.2, 0.15, 0.1, 0.3, 0.15])
            sources.append(f"192.168.1.{user_id}")
            departments.append(dept)
            
            # Назначение
            if np.random.random() > 0.7: # 30% внешний трафик
                # Исправлена обрезанная строка
                destinations.append(f"{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}")
            else: # 70% внутренний трафик
                destinations.append(f"192.168.1.{np.random.randint(1, users + 1)}")
                
            # Протокол и порт
            protocol = np.random.choice(protocols_list, p=[0.3, 0.4, 0.05, 0.05, 0.05, 0.1, 0.05])
            protocols.append(protocol)
            port_map = {'HTTP': 80, 'HTTPS': 443, 'SSH': 22, 'SMTP': 25, 'FTP': 21, 'DNS': 53, 'RDP': 3389}
            ports.append(port_map.get(protocol, np.random.randint(1024, 65535)))
            
            # Размер пакета
            size = np.random.lognormal(mean=10, sigma=2)
            sizes.append(min(int(size), 65535))
            
        self.traffic_df = pd.DataFrame({
            'timestamp': timestamps,
            'source_ip': sources,
            'destination_ip': destinations,
            'protocol': protocols,
            'port': ports,
            'size_bytes': sizes,
            'department': departments
        })
        
        self.traffic_df = self.traffic_df.sort_values('timestamp')
        print(f"Сгенерировано {len(self.traffic_df)} записей трафика")
        return self.traffic_df

    # ЗАДАНИЕ 1: Обнаружение DDoS-атак
    def detect_ddos(self):
        print("\n" + "="*60)
        print("ОБНАРУЖЕНИЕ DDoS-АТАК (Анализ пакетов в секунду/минуту)")
        print("="*60)
        
        # Группируем по IP назначения и минутам
        self.traffic_df['minute'] = self.traffic_df['timestamp'].dt.floor('T')
        pps_analysis = self.traffic_df.groupby(['destination_ip', 'minute']).size().reset_index(name='packet_count')
        
        ddos_threshold = self.anomaly_patterns['ddos_attack']['threshold'] # 1000
        
        potential_ddos = pps_analysis[pps_analysis['packet_count'] > ddos_threshold]
        
        if not potential_ddos.empty:
            print(f"Обнаружены признаки DDoS-атаки! Затронуто целей: {len(potential_ddos)}")
            # Берем самую крупную атаку для примера
            worst_attack = potential_ddos.sort_values('packet_count', ascending=False).iloc[0]
            alert_msg = f"DDoS атака на {worst_attack['destination_ip']}! Пакетов в минуту: {worst_attack['packet_count']}"
            
            logging.critical(alert_msg)
            self.send_telegram_alert(alert_msg)
            
            violation = {
                'type': 'DDOS_ATTACK',
                'timestamp': worst_attack['minute'],
                'source': 'Multiple',
                'details': alert_msg,
                'severity': 'CRITICAL'
            }
            self.policy_violations.append(violation)
        else:
            print("Признаков DDoS-атак не обнаружено (порог не превышен).")

    def detect_policy_violations(self):
        """
        Обнаружение нарушений политик безопасности
        """
        print("\n" + "="*60)
        print("АНАЛИЗ НАРУШЕНИЙ ПОЛИТИК БЕЗОПАСНОСТИ")
        print("="*60)
        violations = []
        
        # 1. Проверка использования заблокированных портов
        blocked_port_violations = self.traffic_df[
            self.traffic_df['port'].isin(self.security_policies['blocked_ports'])
        ]
        if not blocked_port_violations.empty:
            msg = f"Обнаружено использование заблокированных портов: {len(blocked_port_violations)} случаев"
            print(f"{msg}")
            logging.warning(msg)
            self.send_telegram_alert(msg)
            
            for _, row in blocked_port_violations.head().iterrows():
                violation = {
                    'type': 'BLOCKED_PORT',
                    'timestamp': row['timestamp'],
                    'source': row['source_ip'],
                    'details': f"Использование порта {row['port']}",
                    'severity': 'HIGH'
                }
                violations.append(violation)

        # 2. Проверка трафика в нерабочее время
        self.traffic_df['hour'] = self.traffic_df['timestamp'].dt.hour
        after_hours_traffic = self.traffic_df[
            (self.traffic_df['hour'] < self.security_policies['work_hours']['start']) |
            (self.traffic_df['hour'] > self.security_policies['work_hours']['end'])
        ]
        if len(after_hours_traffic) > 100:
            print(f" Подозрительная активность в нерабочее время: {len(after_hours_traffic)} событий")
            logging.warning(f"Активность в нерабочее время: {len(after_hours_traffic)} событий")
            
            dept_analysis = after_hours_traffic.groupby('department').size()
            for dept, count in dept_analysis.items():
                if count > 50:
                    violation = {
                        'type': 'AFTER_HOURS_ACTIVITY',
                        'timestamp': datetime.now(),
                        'source': f"Отдел {dept}",
                        'details': f"{count} сетевых событий в нерабочее время",
                        'severity': 'MEDIUM'
                    }
                    violations.append(violation)

        # 3. Обнаружение сканирования портов
        self.traffic_df['time_window'] = self.traffic_df['timestamp'].dt.floor('5T')
        port_scan_candidates = self.traffic_df.groupby(
            ['source_ip', 'time_window']
        ).agg({
            'port': 'nunique',
            'destination_ip': 'nunique'
        }).reset_index()
        
        potential_scans = port_scan_candidates[
            (port_scan_candidates['port'] > 50) &
            (port_scan_candidates['destination_ip'] > 10)
        ]
        
        if not potential_scans.empty:
            msg = f"Обнаружено потенциальное сканирование портов: {len(potential_scans)} случаев"
            print(f" {msg}")
            logging.warning(msg)
            self.send_telegram_alert(msg)
            
            for _, row in potential_scans.iterrows():
                violation = {
                    'type': 'PORT_SCAN',
                    'timestamp': row['time_window'],
                    'source': row['source_ip'],
                    'details': f"Обращение к {row['port']} портам за 5 минут",
                    'severity': 'HIGH'
                }
                violations.append(violation)
                
        self.policy_violations.extend(violations)
        return violations

    def analyze_traffic_patterns(self):
        """Анализ паттернов трафика"""
        print("\n" + "="*60)
        print("АНАЛИЗ ПАТТЕРНОВ ТРАФИКА")
        print("="*60)
        analysis_results = {}
        
        # 1. Анализ по протоколам
        protocol_distribution = self.traffic_df['protocol'].value_counts()
        print("Распределение по протоколам:")
        for protocol, count in protocol_distribution.items():
            percentage = (count / len(self.traffic_df)) * 100
            print(f"  {protocol}: {count} ({percentage:.1f}%)")
        analysis_results['protocol_distribution'] = protocol_distribution
        
        # 2. Анализ по отделам
        print("Сетевой трафик по отделам:")
        dept_traffic = self.traffic_df.groupby('department').agg({
            'size_bytes': 'sum',
            'source_ip': 'nunique'
        }).sort_values('size_bytes', ascending=False)
        dept_traffic['size_mb'] = dept_traffic['size_bytes'] / (1024 * 1024)
        for dept, row in dept_traffic.iterrows():
            print(f"  {dept}: {row['size_mb']:.1f} МБ от {row['source_ip']} пользователей")
        analysis_results['department_traffic'] = dept_traffic
        
        # 3. Определение внешнего vs внутреннего трафика
        self.traffic_df['is_external'] = ~self.traffic_df['destination_ip'].str.startswith('192.168.1.')
        external_traffic = self.traffic_df['is_external'].sum()
        internal_traffic = len(self.traffic_df) - external_traffic
        print(f"Внешний трафик: {external_traffic} событий ({(external_traffic/len(self.traffic_df))*100:.1f}%)")
        print(f"Внутренний трафик: {internal_traffic} событий ({(internal_traffic/len(self.traffic_df))*100:.1f}%)")
        
        # 4. Объём данных
        total_traffic_mb = self.traffic_df['size_bytes'].sum() / (1024 * 1024)
        print(f"Общий объём трафика: {total_traffic_mb:.1f} МБ")
        return analysis_results

    def generate_security_report(self):
        """Генерация отчета по безопасности"""
        print("\n" + "="*60)
        print("ОТЧЕТ ПО БЕЗОПАСНОСТИ СЕТЕВОГО ТРАФИКА")
        print("="*60)
        print(f"Предприятие: {self.company_name}")
        print(f"Период анализа: {self.traffic_df['timestamp'].min()} - {self.traffic_df['timestamp'].max()}")
        print(f"Всего событий: {len(self.traffic_df)}")
        
        if self.policy_violations:
            print(f"ОБНАРУЖЕННЫЕ НАРУШЕНИЯ: {len(self.policy_violations)}")
            violation_types = defaultdict(int)
            for violation in self.policy_violations:
                violation_types[violation['type']] += 1
            for v_type, count in violation_types.items():
                print(f"  - {v_type}: {count} случаев")
        else:
            print("Критических нарушений не обнаружено")
            
        print("\n" + "-"*60)
        print("РЕКОМЕНДАЦИИ ПО УЛУЧШЕНИЮ БЕЗОПАСНОСТИ:")
        recommendations = []
        
        http_count = len(self.traffic_df[self.traffic_df['protocol'] == 'HTTP'])
        https_count = len(self.traffic_df[self.traffic_df['protocol'] == 'HTTPS'])
        if http_count > https_count * 0.5:
            recommendations.append("Увеличить использование HTTPS вместо HTTP")
            
        unique_ports = self.traffic_df['port'].nunique()
        if unique_ports > 100:
            recommendations.append("Рассмотреть возможность ограничения используемых портов")
            
        if any(v['type'] == 'AFTER_HOURS_ACTIVITY' for v in self.policy_violations):
            recommendations.append("Внедрить строгий контроль доступа в нерабочее время")
            
        if any(v['type'] == 'PORT_SCAN' for v in self.policy_violations):
            recommendations.append("Настроить IDS/IPS для автоматического блокирования сканирования портов")

        if any(v['type'] == 'DDOS_ATTACK' for v in self.policy_violations):
            recommendations.append("Внедрить системы защиты от DDoS (например, Cloudflare или Anti-DDoS)")

        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. {rec}")
        return recommendations

    def visualize_traffic(self):
        """Визуализация данных трафика"""
        print("\n" + "="*60)
        print("ВИЗУАЛИЗАЦИЯ СЕТЕВОГО ТРАФИКА")
        print("="*60)
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle(f'Анализ сетевого трафика предприятия {self.company_name}', fontsize=16)
        
        # 1. Трафик по часам
        hourly_traffic = self.traffic_df.groupby('hour').size()
        axes[0, 0].bar(hourly_traffic.index, hourly_traffic.values)
        axes[0, 0].set_title('Трафик по часам суток')
        axes[0, 0].set_xlabel('Час')
        axes[0, 0].set_ylabel('Количество событий')
        axes[0, 0].axvspan(0, 9, alpha=0.2, color='red', label='Нерабочее время')
        axes[0, 0].axvspan(18, 24, alpha=0.2, color='red')
        axes[0, 0].legend()
        
        # 2. Распределение по протоколам
        protocol_dist = self.traffic_df['protocol'].value_counts()
        axes[0, 1].pie(protocol_dist.values, labels=protocol_dist.index, autopct='%1.1f%%')
        axes[0, 1].set_title('Распределение по протоколам')
        
        # 3. Трафик по отделам (объём)
        dept_traffic = self.traffic_df.groupby('department')['size_bytes'].sum() / (1024 * 1024)
        axes[1, 0].bar(dept_traffic.index, dept_traffic.values)
        axes[1, 0].set_title('Объём трафика по отделам (МБ)')
        axes[1, 0].set_xlabel('Отдел')
        axes[1, 0].set_ylabel('МБ')
        axes[1, 0].tick_params(axis='x', rotation=45)
        
        # 4. Внутренний vs внешний трафик
        external_count = self.traffic_df['is_external'].sum()
        internal_count = len(self.traffic_df) - external_count
        labels = ['Внутренний', 'Внешний']
        values = [internal_count, external_count]
        colors = ['lightblue', 'lightcoral']
        axes[1, 1].bar(labels, values, color=colors)
        axes[1, 1].set_title('Внутренний vs внешний трафик')
        axes[1, 1].set_ylabel('Количество событий')
        
        plt.tight_layout()
        plt.savefig('network_traffic_analysis.png', dpi=150, bbox_inches='tight')
        print("Графики сохранены в файл 'network_traffic_analysis.png'")
        plt.show()

# Основная программа
def main():
    print("="*70)
    print("СИСТЕМА МОНИТОРИНГА СЕТЕВОГО ТРАФИКА ПРЕДПРИЯТИЯ")
    print("Учебный кейс для дисциплины 'Обеспечение ИБ бизнес-процессов'")
    print("="*70)
    
    analyzer = NetworkTrafficAnalyzer(company_name="ТехноПрофи")
    traffic_data = analyzer.simulate_traffic_data(hours=24, users=50)
    analyzer.analyze_traffic_patterns()
    
    # Обнаружение нарушений
    violations = analyzer.detect_policy_violations()
    
    # ЗАДАНИЕ 1: Вызов DDoS-детектора
    analyzer.detect_ddos() 
    
    analyzer.generate_security_report()
    analyzer.visualize_traffic()
    
    print("\n" + "="*70)
    print("КЕЙС УСПЕШНО ЗАВЕРШЁН")
    print("="*70)
    
    print("\nПример записей трафика (первые 5):")
    print(traffic_data.head().to_string())

if __name__ == "__main__":
    main()