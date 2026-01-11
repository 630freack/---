
# Импорт необходимых библиотек
import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import threading
import time
import os
import ctypes
import sys
from collections import defaultdict

# Конфигурация
UPDATE_INTERVAL = 1  # Интервал обновления данных (секунды)
HIGH_TRAFFIC_THRESHOLD = 1024 * 1024  # Порог высокого трафика в байтах/сек (1 МБ/с)

# Список системных процессов, которые нужно фильтровать
SYSTEM_PROCESSES = {
    'system', 'svchost.exe', 'lsass.exe', 'wininit.exe', 'services.exe',
    'lsaiso.exe', 'winlogon.exe', 'fontdrvhost.exe', 'dwm.exe', 'taskhostw.exe',
    'explorer.exe', 'sihost.exe', 'startmenuexperiencehost.exe', 'searchui.exe',
    'runtimebroker.exe', 'audiodg.exe', 'dllhost.exe', 'mpcmdrun.exe',
    'ntoskrnl.exe', 'spoolsv.exe', 'wmpnetwk.exe', 'wisptis.exe', 'wscsvc.exe',
    'wuauserv.exe', 'bits.exe', 'trustedinstaller.exe', 'appinfo.exe',
    'dusmsvc.exe', 'wscsvc.exe', 'securityhealthservice.exe', 'cbdhsvc.exe',
    'dasHost.exe', 'wlanext.exe'
}

class TrafficMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Монитор интернет-трафика")
        self.root.geometry("1000x600")
        
        # Проверка прав администратора
        if not self.is_admin():
            messagebox.showwarning("Предупреждение", "Для корректной работы приложение может требовать прав администратора.\nНекоторые процессы могут не отображаться без повышенных привилегий.")
        
        # Словари для хранения предыдущих данных о трафике
        self.prev_bytes_sent = {}
        self.prev_bytes_recv = {}
        self.prev_time = {}
        
        # Общий объём переданных данных
        self.total_sent = defaultdict(int)
        self.total_recv = defaultdict(int)
        
        # Флаг для управления обновлением
        self.running = False
        
        # Кэш имен процессов
        self.process_names = {}
        
        self.setup_gui()
        
    def is_admin(self):
        """Проверяет, запущено ли приложение с правами администратора"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def setup_gui(self):
        """Настройка графического интерфейса"""
        # Фрейм для кнопок
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)
        
        # Кнопка запуска/остановки
        self.start_stop_btn = tk.Button(button_frame, text="Запустить", command=self.toggle_monitor, width=15, height=2)
        self.start_stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Кнопка обновления
        self.refresh_btn = tk.Button(button_frame, text="Обновить", command=self.refresh_data, width=15, height=2)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
        
        # Кнопка запуска от имени администратора
        self.run_as_admin_btn = tk.Button(button_frame, text="Запустить от имени администратора", command=self.run_as_admin, width=25, height=2)
        self.run_as_admin_btn.pack(side=tk.LEFT, padx=5)
        
        # Фрейм для таблицы
        table_frame = tk.Frame(self.root)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Настройка Treeview (таблицы)
        columns = ("PID", "Приложение", "Скорость загрузки", "Скорость отдачи", "Общий объём (загрузка)", "Общий объём (отдача)")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=25)
        
        # Настройка заголовков
        self.tree.heading("PID", text="PID")
        self.tree.heading("Приложение", text="Приложение")
        self.tree.heading("Скорость загрузки", text="Скорость загрузки")
        self.tree.heading("Скорость отдачи", text="Скорость отдачи")
        self.tree.heading("Общий объём (загрузка)", text="Общий объём (загрузка)")
        self.tree.heading("Общий объём (отдача)", text="Общий объём (отдача)")
        
        # Настройка ширины колонок
        self.tree.column("PID", width=80, anchor='center')
        self.tree.column("Приложение", width=200)
        self.tree.column("Скорость загрузки", width=150, anchor='center')
        self.tree.column("Скорость отдачи", width=150, anchor='center')
        self.tree.column("Общий объём (загрузка)", width=150, anchor='center')
        self.tree.column("Общий объём (отдача)", width=150, anchor='center')
        
        # Добавление прокрутки
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Настройка тегов для цветовой индикации
        self.tree.tag_configure('high_traffic', background='red', foreground='white')
        self.tree.tag_configure('normal', background='white', foreground='black')
    
    def bytes_to_human(self, bytes_value):
        """Преобразует байты в удобочитаемый формат (КБ, МБ, ГБ)"""
        if bytes_value < 1024:
            return f"{bytes_value:.2f} байт/с"
        elif bytes_value < 1024 * 1024:
            return f"{bytes_value / 1024:.2f} КБ/с"
        elif bytes_value < 1024 * 1024 * 1024:
            return f"{bytes_value / (1024 * 1024):.2f} МБ/с"
        else:
            return f"{bytes_value / (1024 * 1024 * 1024):.2f} ГБ/с"
    
    def format_total_data(self, bytes_value):
        """Форматирует общий объём данных"""
        if bytes_value < 1024:
            return f"{bytes_value:.2f} байт"
        elif bytes_value < 1024 * 1024:
            return f"{bytes_value / 1024:.2f} КБ"
        elif bytes_value < 1024 * 1024 * 1024:
            return f"{bytes_value / (1024 * 1024):.2f} МБ"
        else:
            return f"{bytes_value / (1024 * 1024 * 1024):.2f} ГБ"
    
    def get_all_processes_network_usage(self):
        """Получает информацию о сетевой активности всех процессов с помощью глобальной статистики"""
        current_time = time.time()
        process_info = {}
        
        try:
            # Получаем глобальную сетевую статистику для всех интерфейсов
            net_io = psutil.net_io_counters(pernic=False)
            
            # Получаем статистику по всем процессам через psutil.process_iter
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name'].lower()
                    
                    # Пропускаем системные процессы
                    if name in SYSTEM_PROCESSES:
                        continue
                    
                    # Получаем имя процесса
                    process_name = proc.info['name']
                    
                    # Инициализируем записи для процесса
                    if pid not in process_info:
                        process_info[pid] = {
                            'pid': pid,
                            'name': process_name,
                            'bytes_sent': 0,
                            'bytes_recv': 0
                        }
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    print(f"Ошибка при обработке процесса {pid}: {e}")
                    continue

            # Альтернативный подход - использование соединений для определения активных сетевых процессов
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.pid is not None and conn.status == 'ESTABLISHED':
                    try:
                        proc = psutil.Process(conn.pid)
                        name = proc.name().lower()
                        
                        # Пропускаем системные процессы
                        if name in SYSTEM_PROCESSES:
                            continue
                        
                        # Получаем имя процесса
                        process_name = proc.name()
                        pid = conn.pid
                        
                        # Инициализируем запись если её нет
                        if pid not in process_info:
                            process_info[pid] = {
                                'pid': pid,
                                'name': process_name,
                                'bytes_sent': 0,
                                'bytes_recv': 0
                            }
                            
                        # Увеличиваем счётчик активных соединений
                        if 'connections' not in process_info[pid]:
                            process_info[pid]['connections'] = 0
                        process_info[pid]['connections'] += 1
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    except Exception as e:
                        print(f"Ошибка при обработке соединения: {e}")
                        continue
                        
            # Получаем сетевую статистику через io_counters для каждого процесса
            for pid, info in process_info.items():
                try:
                    proc = psutil.Process(pid)
                    with proc.oneshot():
                        io = proc.io_counters()
                        if io:
                            info['bytes_sent'] = io.write_bytes
                            info['bytes_recv'] = io.read_bytes
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Процесс завершился
                    continue
                except Exception as e:
                    print(f"Ошибка при получении IO статистики для процесса {pid}: {e}")
                    continue

            # Форматируем результат
            result = []
            for info in process_info.values():
                pid = info['pid']
                bytes_sent = info['bytes_sent']
                bytes_recv = info['bytes_recv']
                
                # Расчёт скорости
                if pid in self.prev_bytes_sent and pid in self.prev_bytes_recv:
                    time_diff = current_time - self.prev_time[pid]
                    if time_diff > 0:
                        upload_speed = (bytes_sent - self.prev_bytes_sent[pid]) / time_diff
                        download_speed = (bytes_recv - self.prev_bytes_recv[pid]) / time_diff
                    else:
                        upload_speed = 0
                        download_speed = 0
                else:
                    upload_speed = 0
                    download_speed = 0
                
                # Обновляем предыдущие значения
                self.prev_bytes_sent[pid] = bytes_sent
                self.prev_bytes_recv[pid] = bytes_recv
                self.prev_time[pid] = current_time
                
                # Обновляем общий объём данных
                self.total_sent[pid] = bytes_sent
                self.total_recv[pid] = bytes_recv
                
                # Определяем тег для строки (цвет)
                max_speed = max(upload_speed, download_speed)
                tags = ('high_traffic',) if max_speed > HIGH_TRAFFIC_THRESHOLD else ('normal',)
                
                result.append({
                    'pid': pid,
                    'name': info['name'],
                    'upload_speed': upload_speed,
                    'download_speed': download_speed,
                    'total_sent': bytes_sent,
                    'total_recv': bytes_recv,
                    'tags': tags
                })
                
            return result
            
        except Exception as e:
            print(f"Ошибка при получении информации о процессах: {e}")
            return []
    
    def update_table(self):
        """Обновляет таблицу с информацией о трафике"""
        # Очищаем таблицу
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Получаем данные о сетевой активности
        processes = self.get_all_processes_network_usage()
        
        # Сортируем по общей скорости (загрузка + отдача)
        processes.sort(key=lambda x: x['upload_speed'] + x['download_speed'], reverse=True)
        
        # Добавляем данные в таблицу
        for proc in processes:
            self.tree.insert("", tk.END, values=(
                proc['pid'],
                proc['name'],
                self.bytes_to_human(proc['download_speed']),
                self.bytes_to_human(proc['upload_speed']),
                self.format_total_data(proc['total_recv']),
                self.format_total_data(proc['total_sent'])
            ), tags=proc['tags'])
    
    def refresh_data(self):
        """Обновляет данные вручную"""
        if not self.running:
            self.update_table()
    
    def monitor_loop(self):
        """Цикл мониторинга в отдельном потоке"""
        while self.running:
            try:
                self.root.after(0, self.update_table)
                time.sleep(UPDATE_INTERVAL)
            except Exception as e:
                print(f"Ошибка в цикле мониторинга: {e}")
                break
    
    def toggle_monitor(self):
        """Запускает или останавливает мониторинг"""
        if not self.running:
            self.running = True
            self.start_stop_btn.config(text="Остановить")
            # Запуск мониторинга в отдельном потоке
            self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
            self.monitor_thread.start()
        else:
            self.running = False
            self.start_stop_btn.config(text="Запустить")
            
    def run_as_admin(self):
        """Запускает приложение от имени администратора"""
        try:
            # Проверяем, уже ли запущено от имени администратора
            if self.is_admin():
                messagebox.showinfo("Информация", "Приложение уже запущено с правами администратора.")
                return
            
            # Получаем путь к текущему скрипту
            script_path = os.path.abspath(__file__)
            
            # Создаем аргументы для запуска
            params = f'"{script_path}"'
            
            # Запускаем текущий скрипт от имени администратора
            result = ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",  # Глагол "runas" для запуска от имени администратора
                sys.executable,  # Путь к интерпретатору Python
                params,  # Аргументы
                None,
                1  # Показывать окно
            )
            
            # Если код результата > 32, то запрос UAC был успешен
            if result > 32:
                # Закрываем текущее приложение
                self.root.quit()
            else:
                messagebox.showerror("Ошибка", f"Не удалось запустить приложение от имени администратора. Код ошибки: {result}")
                
        except Exception as e:
            messagebox.showerror("Ошибка", f"Произошла ошибка при попытке запуска от имени администратора:\n{str(e)}")

# Функция для запуска приложения
def main():
    root = tk.Tk()
    app = TrafficMonitor(root)
    root.mainloop()

if __name__ == "__main__":
    main()
