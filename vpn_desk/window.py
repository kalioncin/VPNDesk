from __future__ import annotations
import json, shutil, time, hashlib, threading, subprocess, os, platform
from pathlib import Path
from datetime import datetime, date, timedelta, timezone
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QTime
from PySide6.QtGui import QAction, QPainter, QColor, QPen, QBrush
from PySide6.QtWidgets import (QMainWindow,QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,QFrame,
    QStackedWidget,QTableWidget,QTableWidgetItem,QHeaderView,QFileDialog,QMessageBox,QPlainTextEdit,
    QDialog,QDialogButtonBox,QFormLayout,QLineEdit,QSpinBox,QDoubleSpinBox,QCheckBox,QComboBox,
    QSystemTrayIcon,QMenu,QApplication,QProgressBar,QSplitter,QGroupBox,QInputDialog,QTreeWidget,QTreeWidgetItem,QTimeEdit,QScrollArea,QRadioButton,QButtonGroup)
from .database import Database
from .settings import Settings
from .importer import read_file, read_pasted
from .checker import check_tcp, classify_transport, run_tcp_checks, CheckCancelled
from .sources import fetch_source, SourceError
from .reporter import publish_github
from .secure_store import get_token, set_token

DARK='''QWidget{background:#11151d;color:#e8edf5;font-family:Segoe UI;font-size:10pt} QFrame#card{background:#1a2230;border:1px solid #293447;border-radius:12px} QPushButton{background:#27364b;border:0;border-radius:8px;padding:9px 14px;color:#f3f6fb} QPushButton:hover{background:#344761} QPushButton#primary{background:#4f7cff;color:white;font-weight:600} QPushButton#danger{background:#793b45} QLineEdit,QPlainTextEdit,QSpinBox,QDoubleSpinBox,QComboBox{background:#0d121a;border:1px solid #344258;border-radius:7px;padding:8px;color:#f0f4fa} QTableWidget{background:#151c27;alternate-background-color:#1b2533;gridline-color:#2c394d;border:1px solid #2b394d;border-radius:8px} QHeaderView::section{background:#202b3b;color:#b9c8dc;padding:8px;border:0} QProgressBar{background:#202b3b;border:0;border-radius:5px;text-align:center;height:9px} QProgressBar::chunk{background:#5b8cff;border-radius:5px} QCheckBox{spacing:8px}'''
LIGHT='''QWidget{background:#f3f6fa;color:#172033;font-family:Segoe UI;font-size:10pt} QFrame#card{background:white;border:1px solid #dce4ee;border-radius:12px} QPushButton{background:#e5ebf4;border:0;border-radius:8px;padding:9px 14px;color:#172033} QPushButton:hover{background:#d5e0ef} QPushButton#primary{background:#356df3;color:white;font-weight:600} QPushButton#danger{background:#f5dfe2} QLineEdit,QPlainTextEdit,QSpinBox,QDoubleSpinBox,QComboBox{background:white;border:1px solid #cbd6e4;border-radius:7px;padding:8px;color:#172033} QTableWidget{background:white;alternate-background-color:#f3f6fa;gridline-color:#dce4ee;border:1px solid #dce4ee;border-radius:8px} QHeaderView::section{background:#e8eef6;color:#34445b;padding:8px;border:0} QProgressBar{background:#e3eaf3;border:0;border-radius:5px;text-align:center;height:9px} QProgressBar::chunk{background:#356df3;border-radius:5px}'''

class Job(QThread):
    done=Signal(object)
    progress=Signal(int,int,object)
    def __init__(self, fn):
        super().__init__(); self.fn=fn; self.cancel_event=threading.Event(); self.pause_event=threading.Event()
    def cancel(self): self.cancel_event.set(); self.pause_event.clear()
    def toggle_pause(self):
        if self.pause_event.is_set(): self.pause_event.clear(); return False
        self.pause_event.set(); return True
    def run(self):
        try: self.done.emit((True,self.fn(self)))
        except Exception as e: self.done.emit((False,e))

class StatusCharts(QWidget):
    def __init__(self,parent=None):
        super().__init__(parent); self.total=0; self.alive=0; self.dead=0; self.latencies=[]; self.setMinimumHeight(190)
    def set_data(self,total,alive,dead,latencies):
        self.total=total; self.alive=alive; self.dead=dead; self.latencies=latencies[:250]; self.update()
    def paintEvent(self,event):
        p=QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w=self.width(); h=self.height(); p.setPen(self.palette().text().color())
        p.drawText(12,20,'Состояние каталога')
        cx,cy=90,112; radius=62; checked=self.alive+self.dead
        if checked:
            p.setBrush(QColor('#39b980')); p.setPen(Qt.NoPen); p.drawPie(cx-radius,cy-radius,2*radius,2*radius,0,int(360* self.alive/checked*16))
            p.setBrush(QColor('#e16b72')); p.drawPie(cx-radius,cy-radius,2*radius,2*radius,int(360*self.alive/checked*16),int(360*self.dead/checked*16))
            p.setBrush(self.palette().window().color()); p.drawEllipse(cx-34,cy-34,68,68)
        else:
            p.setBrush(QColor('#718096')); p.drawEllipse(cx-radius,cy-radius,2*radius,2*radius)
        p.setPen(self.palette().text().color()); p.drawText(cx-25,cy+5,str(checked))
        p.drawText(175,70,f'Всего: {self.total}'); p.drawText(175,100,f'Успешно: {self.alive}'); p.drawText(175,130,f'Неуспешно: {self.dead}'); p.drawText(175,160,f'Не проверено: {max(0,self.total-checked)}')
        sx=max(360,w//2); p.drawText(sx,20,'Задержка последних проверок')
        plot_w=max(100,w-sx-25); plot_h=125; top=42
        p.setPen(QPen(self.palette().mid().color(),1)); p.drawRect(sx,top,plot_w,plot_h)
        if self.latencies:
            vals=[max(0,float(v or 0)) for v in self.latencies]
            maxv=max(100,max(vals))
            p.setPen(QPen(QColor('#6f9cff'),3))
            for i,v in enumerate(vals):
                x=sx+5+int((plot_w-10)*i/max(1,len(vals)-1)); y=top+plot_h-5-int((plot_h-10)*min(v,maxv)/maxv); p.drawPoint(x,y)
            p.setPen(self.palette().text().color()); p.drawText(sx,top+plot_h+18,f'Макс. шкала: {maxv:.0f} мс')
        else:
            p.setPen(self.palette().mid().color()); p.drawText(sx+12,top+68,'Пока нет измерений')

class PreviewDialog(QDialog):
    def __init__(self, parent, items, errors, title='Предпросмотр импорта'):
        super().__init__(parent); self.setWindowTitle(title); self.resize(760,520)
        layout=QVBoxLayout(self)
        summary=QLabel(f'Найдено записей: {len(items)} · Ошибок разбора: {len(errors)}\nСомнительные записи не исправляются автоматически.')
        layout.addWidget(summary)
        table=QTableWidget(0,4); table.setHorizontalHeaderLabels(['Тип','Протокол','Адрес / URL','Порт']); table.horizontalHeader().setSectionResizeMode(2,QHeaderView.Stretch)
        for item in items[:1000]:
            r=table.rowCount(); table.insertRow(r)
            vals=['Источник' if item.kind=='source' else 'Конфигурация',item.protocol or '—',item.host or item.value[:180],str(item.port or '—')]
            for c,v in enumerate(vals): table.setItem(r,c,QTableWidgetItem(v))
        layout.addWidget(table)
        if len(items)>1000:
            layout.addWidget(QLabel(f'В таблице показаны первые 1000 из {len(items)} записей. При подтверждении будут импортированы все распознанные записи.'))
        if errors:
            err=QPlainTextEdit(); err.setReadOnly(True); err.setMaximumHeight(110)
            err.setPlainText('\n'.join(f'{a}: {b}' for a,b in errors[:100])); layout.addWidget(err)
        self.test_sources=QCheckBox('Сначала проверить URL-источники и загрузить найденные конфигурации')
        self.test_sources.setChecked(False)
        if any(x.kind=='source' for x in items): layout.addWidget(self.test_sources)
        buttons=QDialogButtonBox(QDialogButtonBox.Ok|QDialogButtonBox.Cancel); buttons.button(QDialogButtonBox.Ok).setText('Продолжить'); buttons.button(QDialogButtonBox.Cancel).setText('Отмена')
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject); layout.addWidget(buttons)

class SettingsDialog(QDialog):
    def __init__(self,parent,settings):
        super().__init__(parent); self.setWindowTitle('Настройки VPNDesk'); self.resize(620,780); self.settings=settings
        root=QVBoxLayout(self); scroll=QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.NoFrame); content=QWidget(); f=QFormLayout(content); scroll.setWidget(content); root.addWidget(scroll)
        self.theme=QComboBox(); self.theme.addItems(['dark','light']); self.theme.setCurrentText(settings.data['theme'])
        self.timeout=QDoubleSpinBox(); self.timeout.setRange(1,30); self.timeout.setValue(float(settings.data['tcp_timeout']))
        self.protocol_timeout=QDoubleSpinBox(); self.protocol_timeout.setRange(3,60); self.protocol_timeout.setValue(float(settings.data.get('protocol_timeout',10)))
        self.workers=QSpinBox(); self.workers.setRange(1,128); self.workers.setValue(int(settings.data['max_workers']))
        self.interval=QSpinBox(); self.interval.setRange(15,10080); self.interval.setValue(int(settings.data['schedule_minutes']))
        self.schedule=QCheckBox('Включить расписание (после подтверждения)'); self.schedule.setChecked(settings.data['schedule_enabled'])
        self.folders=QLineEdit(';'.join(settings.data.get('watch_folders',[]))); self.folders.setPlaceholderText('Папки через точку с запятой')
        self.maxfile=QSpinBox(); self.maxfile.setRange(1,4096); self.maxfile.setValue(int(settings.data['max_file_mb']))
        self.maxzip=QSpinBox(); self.maxzip.setRange(1,8192); self.maxzip.setValue(int(settings.data['max_archive_unpacked_mb']))
        self.watch=QCheckBox('Следить за выбранными папками'); self.watch.setChecked(settings.data['watch_enabled'])
        self.github=QCheckBox('Автоматически публиковать очищенную статистику'); self.github.setChecked(settings.data['github_auto'])
        self.repo=QLineEdit(settings.data['github_repo']); self.token=QLineEdit(get_token()); self.token.setEchoMode(QLineEdit.Password)
        self.branch=QLineEdit(settings.data['github_branch']); self.path=QLineEdit(settings.data['github_path'])
        self.tray=QCheckBox('Использовать системный трей'); self.tray.setChecked(settings.data['tray_enabled'])
        self.energy=QCheckBox('Энергосберегающий режим: ограничить число проверяемых записей'); self.energy.setChecked(settings.data['energy_saving_enabled'])
        self.energy_limit=QSpinBox(); self.energy_limit.setRange(1,1000000); self.energy_limit.setValue(int(settings.data['energy_check_limit']))
        self.portable=QCheckBox('Портативный режим (данные рядом с программой)'); self.portable.setChecked(settings.data['portable_mode'])
        self.auto_load=QCheckBox('Автоматически подбирать нагрузку по характеристикам ПК'); self.auto_load.setChecked(settings.data['auto_load'])
        self.shutdown=QCheckBox('После последней проверки выключать компьютер'); self.shutdown.setChecked(settings.data['auto_shutdown_enabled'])
        self.shutdown_time=QTimeEdit(); self.shutdown_time.setDisplayFormat('HH:mm'); self.shutdown_time.setTime(QTime.fromString(settings.data['auto_shutdown_time'],'HH:mm'))
        self.maintenance=QCheckBox('Автоматическое обслуживание и резервные копии'); self.maintenance.setChecked(settings.data['maintenance_enabled'])
        self.maintenance_days=QSpinBox(); self.maintenance_days.setRange(1,90); self.maintenance_days.setValue(int(settings.data['maintenance_interval_days']))
        f.addRow('Тема',self.theme); f.addRow('Тайм-аут TCP (сек.)',self.timeout); f.addRow('Тайм-аут полной VPN-проверки (сек.)',self.protocol_timeout); f.addRow('Максимум потоков',self.workers)
        f.addRow('Интервал расписания (мин.)',self.interval); f.addRow(self.schedule); f.addRow('Папки наблюдения (;)',self.folders); f.addRow('Лимит одного файла (МБ)',self.maxfile); f.addRow('Лимит распаковки ZIP (МБ)',self.maxzip)
        f.addRow(self.watch); f.addRow(self.tray); f.addRow(self.auto_load); f.addRow(self.energy); f.addRow('Лимит ключей за цикл',self.energy_limit); f.addRow(self.portable); f.addRow(self.shutdown); f.addRow('Время финальной проверки',self.shutdown_time); f.addRow(self.maintenance); f.addRow('Интервал обслуживания (дней)',self.maintenance_days)
        f.addRow(self.github); f.addRow('GitHub owner/repo',self.repo); f.addRow('GitHub token',self.token); f.addRow('Ветка',self.branch); f.addRow('Путь отчёта',self.path)
        note=QLabel('В GitHub отправляются только счётчики и дата. URI, адреса, порты и секреты конфигураций не публикуются.'); note.setWordWrap(True); f.addRow(note)
        buttons=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel); buttons.accepted.connect(self.save); buttons.rejected.connect(self.reject); f.addRow(buttons)
        reset=QPushButton('Сбросить настройки'); reset.clicked.connect(self.reset_settings); f.addRow(reset)
    def reset_settings(self):
        if QMessageBox.question(self,'Сброс настроек','Вернуть настройки к исходным? База и конфигурации останутся нетронутыми.')==QMessageBox.Yes:
            self.settings.reset()
            set_token('')
            self.parent().apply_theme()
            QMessageBox.information(self,'Готово','Настройки сброшены. База и конфигурации остались нетронутыми.')
            self.reject()
    def save(self):
        if not set_token(self.token.text().strip()):
            QMessageBox.warning(self,'Хранилище секретов недоступно','Не удалось сохранить GitHub-токен в системном хранилище. Токен не будет записан в обычный settings.json.'); self.token.clear()
        d=self.settings.data; d.update(theme=self.theme.currentText(),tcp_timeout=self.timeout.value(),protocol_timeout=self.protocol_timeout.value(),max_workers=self.workers.value(),schedule_minutes=self.interval.value(),schedule_enabled=self.schedule.isChecked(),watch_folders=[x.strip() for x in self.folders.text().split(';') if x.strip()],max_file_mb=self.maxfile.value(),max_archive_unpacked_mb=self.maxzip.value(),watch_enabled=self.watch.isChecked(),tray_enabled=self.tray.isChecked(),auto_load=self.auto_load.isChecked(),energy_saving_enabled=self.energy.isChecked(),energy_check_limit=self.energy_limit.value(),portable_mode=self.portable.isChecked(),auto_shutdown_enabled=self.shutdown.isChecked(),auto_shutdown_time=self.shutdown_time.time().toString('HH:mm'),maintenance_enabled=self.maintenance.isChecked(),maintenance_interval_days=self.maintenance_days.value(),github_auto=self.github.isChecked(),github_repo=self.repo.text().strip(),github_branch=self.branch.text().strip() or 'main',github_path=self.path.text().strip() or 'reports/vpndesk-stats.json')
        self.settings.save(); self.accept()

class MainWindow(QMainWindow):
    def __init__(self, data_dir:Path):
        super().__init__(); self.data_dir=data_dir; self.data_dir.mkdir(parents=True,exist_ok=True)
        self.db=Database(data_dir/'vpndesk.db'); self.settings=Settings(data_dir/'settings.json'); self.job=None; self._watch_seen={}; self._last_report=int(time.time()); self._db_closed=False; self._closing=False; self._shutdown_last_date=''; self._shutdown_pending=False; self._last_maintenance=''
        self.setWindowTitle('VPNDesk'); self.resize(1180,760); self.setMinimumSize(940,620)
        root=QWidget(); self.setCentralWidget(root); outer=QHBoxLayout(root); outer.setContentsMargins(14,14,14,14); outer.setSpacing(14)
        nav=QFrame(); nav.setObjectName('card'); nav.setFixedWidth(205); nv=QVBoxLayout(nav)
        brand=QLabel('VPNDesk'); brand.setStyleSheet('font-size:24px;font-weight:700;padding:12px;color:#75a0ff'); nv.addWidget(brand)
        self.stack=QStackedWidget(); self.pages={}
        for name,title in [('Обзор','Обзор'),('Источники','Источники'),('Карта источников','Карта источников'),('Конфигурации','Конфигурации'),('Импорт','Импорт'),('Качество данных','Качество данных'),('Аналитика','Аналитика'),('Производительность','Производительность'),('Обслуживание','Обслуживание'),('Компоненты','Компоненты'),('Журнал','Центр событий')]:
            b=QPushButton(title); b.setCursor(Qt.PointingHandCursor); b.clicked.connect(lambda checked=False,n=name:self.show_page(n)); nv.addWidget(b)
        nv.addStretch(); settings_btn=QPushButton('⚙  Настройки'); settings_btn.clicked.connect(self.open_settings); nv.addWidget(settings_btn)
        outer.addWidget(nav); outer.addWidget(self.stack,1)
        self.build_overview(); self.build_sources(); self.build_source_map(); self.build_configs(); self.build_import(); self.build_quality(); self.build_analytics(); self.build_performance(); self.build_maintenance(); self.build_components(); self.build_logs()
        self.apply_theme(); self.refresh_all()
        self.tray=None
        if QSystemTrayIcon.isSystemTrayAvailable() and self.settings.data['tray_enabled']:
            self.tray=QSystemTrayIcon(self); self.tray.setToolTip('VPNDesk'); menu=QMenu(); a=menu.addAction('Открыть VPNDesk'); a.triggered.connect(self.showNormal); q=menu.addAction('Выход'); q.triggered.connect(self.exit_app); self.tray.setContextMenu(menu); self.tray.activated.connect(lambda reason:self.showNormal() if reason==QSystemTrayIcon.DoubleClick else None); self.tray.show()
        self.timer=QTimer(self); self.timer.timeout.connect(self.periodic); self.timer.start(60000)
        self.db.add_event('VPNDesk запущен'); self.check_hardware_profile(); self.update_performance(); self.update_analytics(); self.update_quality()
        QTimer.singleShot(350, self.first_run_setup)

    def first_run_setup(self):
        if self.settings.data.get('onboarding_completed'):
            return
        answer=QMessageBox.question(self,'Первый запуск VPNDesk',
            'Перед добавлением большого списка источников предлагаю проверить характеристики компьютера и выбрать профиль нагрузки.\n\n'
            'Проверка короткая и безопасная: она не пытается зависать или перегружать Windows. Выполнить? ',
            QMessageBox.Yes|QMessageBox.No, QMessageBox.Yes)
        if answer==QMessageBox.Yes:
            self.check_hardware_profile()
            hp=self.hardware_profile
            bench_start=time.perf_counter(); loops=0; accumulator=0
            while time.perf_counter()-bench_start<0.15:
                accumulator += sum(i*i for i in range(1200)); loops += 1
            bench_ms=round((time.perf_counter()-bench_start)*1000)
            self.settings.data['startup_cpu_benchmark']={'duration_ms':bench_ms,'iterations':loops}
            self.settings.save()
            QMessageBox.information(self,'Проверка компьютера завершена',
                f"Базовая диагностика и короткий CPU-тест завершены.\nПроцессор: {hp.get('cpu_count','?')} логических ядер\nОЗУ: {hp.get('ram_gb','?')} ГБ\nСвободное место: {hp.get('disk_gb','?')} ГБ\nCPU-тест: {loops} циклов за {bench_ms} мс\n\nЭто короткий замер, а не стресс-тест. Тяжёлый режим не будет намеренно вызывать зависания: параллельность всё равно ограничивается характеристиками ПК.")
        choices=['Лёгкий — бережная нагрузка, дольше; подходит для больших списков и небольших партий',
                 'Средний — баланс скорости и стабильности (рекомендуется)',
                 'Интенсивный — быстрее, выше нагрузка; защитные ограничения останутся включены']
        choice,ok=QInputDialog.getItem(self,'Профиль проверки','Выбери план обработки:',choices,1,False)
        if not ok: choice=choices[1]
        plan=choices.index(choice)
        profiles=[(4,8.0),(12,4.0),(24,2.5)]
        workers,timeout=profiles[plan]
        # Bound concurrency to the available hardware; never deliberately stress/freeze the PC.
        ram=float(getattr(self,'hardware_profile',{}).get('ram_gb') or 4)
        cpu=int(getattr(self,'hardware_profile',{}).get('cpu_count') or 2)
        safe_cap=max(2,min(workers,cpu*2,int(max(2,ram)*2),32))
        self.settings.data.update(onboarding_completed=True,performance_plan=['light','balanced','intensive'][plan],
                                  max_workers=safe_cap,tcp_timeout=timeout,protocol_timeout=min(12.0,max(4.0,timeout*2)))
        self.settings.save()
        self.db.add_event(f'Выбран профиль нагрузки: {self.settings.data["performance_plan"]}, потоков: {safe_cap}')
        self.status_label.setText(f'Профиль нагрузки установлен: {choice.split(" — ")[0]}. Можно вставлять источники и сначала тестировать их.')
        self.refresh_all()

    def page(self,name):
        content=QWidget(); l=QVBoxLayout(content); l.setContentsMargins(8,8,8,8); l.setSpacing(12)
        scroll=QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.NoFrame); scroll.setWidget(content)
        self.pages[name]=(scroll,l); self.stack.addWidget(scroll); return l
    def heading(self,l,title,sub=''):
        t=QLabel(title); t.setStyleSheet('font-size:23px;font-weight:700'); l.addWidget(t)
        if sub: s=QLabel(sub); s.setStyleSheet('color:#8d9bb0'); l.addWidget(s)
    def card(self,parent,title,value,sub):
        c=QFrame(); c.setObjectName('card'); v=QVBoxLayout(c); a=QLabel(title); a.setStyleSheet('color:#92a5c0'); n=QLabel(str(value)); n.setStyleSheet('font-size:27px;font-weight:700'); d=QLabel(sub); d.setStyleSheet('color:#92a5c0'); v.addWidget(a); v.addWidget(n); v.addWidget(d); return c
    def build_overview(self):
        l=self.page('Обзор'); self.heading(l,'Добро пожаловать в VPNDesk','Каталог, быстрая TCP-проверка и реальная проверка протокола через изолированный sing-box без системного VPN-туннеля.')
        row=QHBoxLayout(); self.stat_labels={}
        for key,title in [('configs','Всего конфигураций'),('reachable','Последняя проверка успешна'),('unreachable','Последняя проверка неуспешна'),('unchecked','Не проверено'),('sources','Источников'),('quarantined','Карантин')]:
            c=self.card(self,title,'0','Локальная база'); row.addWidget(c); self.stat_labels[key]=c.findChildren(QLabel)[1]
        l.addLayout(row)
        actions=QHBoxLayout(); imp=QPushButton('＋ Импортировать'); imp.setObjectName('primary'); imp.clicked.connect(self.pick_files); actions.addWidget(imp); paste=QPushButton('Вставить текст'); paste.clicked.connect(self.paste_text); actions.addWidget(paste); src=QPushButton('Добавить URL'); src.clicked.connect(self.add_source_dialog); actions.addWidget(src); self.start_check_btn=QPushButton('▶ Быстрая TCP-проверка'); self.start_check_btn.setObjectName('primary'); self.start_check_btn.clicked.connect(self.check_configs); actions.addWidget(self.start_check_btn); l.addLayout(actions); actions2=QHBoxLayout(); self.full_check_btn=QPushButton('Полная VPN-проверка через sing-box'); self.full_check_btn.clicked.connect(self.check_protocol_configs); actions2.addWidget(self.full_check_btn); self.pause_btn=QPushButton('Ⅱ Пауза'); self.pause_btn.clicked.connect(self.pause_job); self.pause_btn.setEnabled(False); actions2.addWidget(self.pause_btn); self.stop_btn=QPushButton('■ Стоп'); self.stop_btn.setObjectName('danger'); self.stop_btn.clicked.connect(self.stop_job); self.stop_btn.setEnabled(False); actions2.addWidget(self.stop_btn); self.cancel_shutdown_btn=QPushButton('Отменить выключение'); self.cancel_shutdown_btn.clicked.connect(self.cancel_shutdown); self.cancel_shutdown_btn.hide(); actions2.addWidget(self.cancel_shutdown_btn); actions2.addStretch(); l.addLayout(actions2)
        self.status_label=QLabel('Готово. Импортируйте файл или добавьте источник.'); self.status_label.setWordWrap(True); l.addWidget(self.status_label)
        self.progress=QProgressBar(); self.progress.setRange(0,100); self.progress.hide(); l.addWidget(self.progress)
        self.charts=StatusCharts(); charts_box=QFrame(); charts_box.setObjectName('card'); cb=QVBoxLayout(charts_box); cb.addWidget(self.charts); l.addWidget(charts_box)
        box=QFrame(); box.setObjectName('card'); bl=QVBoxLayout(box); bl.addWidget(QLabel('Последние события')); self.recent=QPlainTextEdit(); self.recent.setReadOnly(True); self.recent.setMaximumHeight(150); bl.addWidget(self.recent); l.addWidget(box); l.addStretch()
    def make_table(self,cols):
        t=QTableWidget(0,len(cols)); t.setHorizontalHeaderLabels(cols); t.setAlternatingRowColors(True); t.setSelectionBehavior(QTableWidget.SelectRows); t.setSelectionMode(QTableWidget.ExtendedSelection); t.setEditTriggers(QTableWidget.NoEditTriggers); t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents); t.horizontalHeader().setStretchLastSection(True); return t
    def build_sources(self):
        l=self.page('Источники'); self.heading(l,'Источники','Мягкий рейтинг учитывает историю проверок, свежесть, задержку и стабильность. Единичные сбои бесплатных узлов не обрушивают оценку.')
        row=QHBoxLayout(); b=QPushButton('＋ Добавить URL'); b.setObjectName('primary'); b.clicked.connect(self.add_source_dialog); row.addWidget(b); allb=QPushButton('Проверить все активные'); allb.clicked.connect(self.check_all_sources); row.addWidget(allb); r=QPushButton('Проверить выбранный'); r.clicked.connect(self.check_selected_source); row.addWidget(r); row.addStretch(); l.addLayout(row)
        row2=QHBoxLayout(); edit=QPushButton('Изменить URL'); edit.clicked.connect(self.edit_source); row2.addWidget(edit); toggle=QPushButton('Включить / отключить'); toggle.clicked.connect(self.toggle_source); row2.addWidget(toggle); restore=QPushButton('Вернуть из карантина'); restore.clicked.connect(self.restore_source); row2.addWidget(restore); delete=QPushButton('Удалить выбранные'); delete.setObjectName('danger'); delete.clicked.connect(self.delete_source); row2.addWidget(delete); sel=QPushButton('Выбрать все'); sel.clicked.connect(lambda:self.source_table.selectAll()); row2.addWidget(sel); clr=QPushButton('Снять выбор'); clr.clicked.connect(lambda:self.source_table.clearSelection()); row2.addWidget(clr); row2.addStretch(); l.addLayout(row2)
        self.source_table=self.make_table(['ID','URL','Статус','Рейтинг','Конфигураций','Успешных конфигураций','Ошибки','Последняя проверка']); l.addWidget(self.source_table)
        tip=QLabel('HTTP 429 и временные серверные ошибки не должны автоматически отправлять источник в карантин. Удаление источника не удаляет сами конфигурации.'); tip.setWordWrap(True); l.addWidget(tip)
    def build_source_map(self):
        l=self.page('Карта источников'); self.heading(l,'Карта источников','Связи показывают, из каких источников пришли конфигурации. Это карта происхождения данных, не географическая карта серверов.')
        self.source_tree=QTreeWidget(); self.source_tree.setHeaderLabels(['Источник / конфигурация','Статус','Рейтинг / протокол']); self.source_tree.setColumnWidth(0,520); l.addWidget(self.source_tree)

    def build_configs(self):
        l=self.page('Конфигурации'); self.heading(l,'Конфигурации','Быстрый TCP-тест проверяет порт; полная проверка через sing-box подтверждает сетевой ответ через саму конфигурацию.')
        row=QHBoxLayout(); b=QPushButton('Быстрая TCP-проверка'); b.setObjectName('primary'); b.clicked.connect(self.check_configs); row.addWidget(b); full=QPushButton('Полная VPN-проверка (sing-box)'); full.clicked.connect(self.check_protocol_configs); row.addWidget(full); sel=QPushButton('Выбрать все'); sel.clicked.connect(lambda:self.config_table.selectAll()); row.addWidget(sel); clr=QPushButton('Снять выбор'); clr.clicked.connect(lambda:self.config_table.clearSelection()); row.addWidget(clr); row.addStretch(); l.addLayout(row)
        row2=QHBoxLayout(); history=QPushButton('История выбранной'); history.clicked.connect(self.show_config_history); row2.addWidget(history); exp=QPushButton('Экспорт TXT'); exp.clicked.connect(self.export_configs); row2.addWidget(exp); delete=QPushButton('Удалить выбранные'); delete.setObjectName('danger'); delete.clicked.connect(self.delete_configs); row2.addWidget(delete); row2.addStretch(); l.addLayout(row2)
        self.config_table=self.make_table(['ID','Протокол','Адрес','Порт','Транспорт','Статус','Задержка мс','Стабильность','Оценка','Тип проверки']); l.addWidget(self.config_table)
        self.udp_note=QLabel('Быстрый TCP-тест не проверяет UDP. Полная проверка sing-box поддерживает Hysteria2/TUIC и другие совместимые UDP-протоколы.'); self.udp_note.setWordWrap(True); l.addWidget(self.udp_note)
    def build_import(self):
        l=self.page('Импорт'); self.heading(l,'Песочница импорта','Файлы сначала анализируются отдельно. Исходники не меняются; в базу данные попадут только после предпросмотра и подтверждения.')
        self.paste=QPlainTextEdit(); self.paste.setPlaceholderText('Вставьте URL источников и конфигурации vless://, vmess://, trojan://, ss://, hysteria2://, tuic://'); l.addWidget(self.paste,1)
        row=QHBoxLayout(); b=QPushButton('Разобрать и показать предпросмотр'); b.setObjectName('primary'); b.clicked.connect(self.preview_paste); row.addWidget(b); f=QPushButton('Загрузить файлы'); f.clicked.connect(self.pick_files); row.addWidget(f); z=QPushButton('Выбрать ZIP'); z.clicked.connect(lambda:self.pick_files(zip_only=True)); row.addWidget(z); l.addLayout(row)
    def build_quality(self):
        l=self.page('Качество данных'); self.heading(l,'Качество данных','Ошибки импорта, повторные записи, непроверенные элементы и старые недоступные конфигурации.')
        self.quality_summary=QLabel('Загрузка…'); self.quality_summary.setWordWrap(True); l.addWidget(self.quality_summary)
        self.import_table=self.make_table(['Дата','Файл','Добавлено','Дубликаты','Ошибки']); l.addWidget(self.import_table)
        b=QPushButton('Обновить показатели'); b.clicked.connect(self.update_quality); l.addWidget(b)

    def build_analytics(self):
        l=self.page('Аналитика'); self.heading(l,'Умная аналитика','Рекомендации строятся по локальной статистике. Они ничего не меняют без подтверждения.')
        self.analytics_text=QPlainTextEdit(); self.analytics_text.setReadOnly(True); l.addWidget(self.analytics_text,1)
        b=QPushButton('Обновить анализ'); b.clicked.connect(self.update_analytics); l.addWidget(b)
    def build_performance(self):
        l=self.page('Производительность'); self.heading(l,'Производительность','Мониторинг нагрузки и характеристик устройства. Показатели обновляются автоматически.')
        self.performance_labels={}
        for key,title in [('cpu','CPU'),('ram','Оперативная память'),('disk','Свободное место'),('workers','Параллельность'),('hardware','Профиль устройства')]:
            c=self.card(self,title,'—','Текущие показатели'); l.addWidget(c); self.performance_labels[key]=c.findChildren(QLabel)[1]
        self.diag_label=QLabel('Самодиагностика ещё не запускалась.'); self.diag_label.setWordWrap(True); l.addWidget(self.diag_label)
        b=QPushButton('Запустить самодиагностику'); b.clicked.connect(self.run_diagnostics); l.addWidget(b)
    def build_maintenance(self):
        l=self.page('Обслуживание'); self.heading(l,'Обслуживание','Резервные копии, целостность базы и очистка с предварительным просмотром.')
        row=QHBoxLayout(); backup=QPushButton('Создать резервную копию'); backup.clicked.connect(self.create_backup); row.addWidget(backup); integrity=QPushButton('Проверить базу'); integrity.clicked.connect(self.check_integrity); row.addWidget(integrity); cleanup=QPushButton('Умная очистка'); cleanup.clicked.connect(self.smart_cleanup); row.addWidget(cleanup); l.addLayout(row)
        self.maintenance_info=QLabel('Автоматическое обслуживание можно включить в настройках. Удаление старых конфигураций всегда требует подтверждения.'); self.maintenance_info.setWordWrap(True); l.addWidget(self.maintenance_info); l.addStretch()

    def build_components(self):
        l=self.page('Компоненты'); self.heading(l,'Менеджер компонентов','Загрузка только с официального GitHub SagerNet. Архив проверяется по SHA-256 до установки.')
        self.component_info=QLabel('sing-box: не проверен'); self.component_info.setWordWrap(True); l.addWidget(self.component_info)
        row=QHBoxLayout(); check=QPushButton('Проверить официальную версию'); check.clicked.connect(self.check_component_update); row.addWidget(check); install=QPushButton('Скачать / обновить sing-box'); install.setObjectName('primary'); install.clicked.connect(self.install_component); row.addWidget(install); l.addLayout(row)
        note=QLabel('Компонент сохраняется в папке данных VPNDesk\\components\\sing-box. Сейчас он устанавливается и проверяется отдельно; он не запускает VPN, не меняет маршруты/DNS и пока не участвует в проверке протокольных рукопожатий.')
        note.setWordWrap(True); l.addWidget(note); l.addStretch(); self.update_component_info()

    def build_logs(self):
        l=self.page('Журнал'); self.heading(l,'Журнал событий','Технические события без сохранения полных URI конфигураций.')
        self.log_table=self.make_table(['Время','Уровень','Событие']); l.addWidget(self.log_table)
        b=QPushButton('Очистить журнал'); b.clicked.connect(self.clear_logs); l.addWidget(b)
    def check_hardware_profile(self):
        try:
            import psutil
            mem=psutil.virtual_memory().total
            disk=psutil.disk_usage(str(self.data_dir)).total
        except Exception:
            mem=0; disk=0
            try:
                import ctypes
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_=[('dwLength',ctypes.c_ulong),('dwMemoryLoad',ctypes.c_ulong),('ullTotalPhys',ctypes.c_ulonglong),('ullAvailPhys',ctypes.c_ulonglong),('ullTotalPageFile',ctypes.c_ulonglong),('ullAvailPageFile',ctypes.c_ulonglong),('ullTotalVirtual',ctypes.c_ulonglong),('ullAvailVirtual',ctypes.c_ulonglong),('ullAvailExtendedVirtual',ctypes.c_ulonglong)]
                m=MEMORYSTATUSEX(); m.dwLength=ctypes.sizeof(m)
                if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)): mem=m.ullTotalPhys
            except Exception: pass
            try:
                import shutil
                disk=shutil.disk_usage(str(self.data_dir)).total
            except Exception: pass
        profile={'cpu_count':os.cpu_count() or 1,'ram_gb':round(mem/1024**3,1),'disk_gb':round(disk/1024**3,1),'platform':platform.system()}
        old=self.settings.data.get('hardware_profile') or {}
        if old and old!=profile:
            self.db.add_event(f'Обнаружено изменение характеристик устройства: {old.get("ram_gb")} → {profile["ram_gb"]} ГБ RAM','INFO')
        if self.settings.data.get('auto_load',True):
            ram_gb=profile['ram_gb'] or 4
            plan=self.settings.data.get('performance_plan','')
            base,plan_timeout={'light':(4,8.0),'balanced':(12,4.0),'intensive':(24,2.5)}.get(plan,(max(2,min(32,profile['cpu_count']*2,int(ram_gb*2))),float(self.settings.data.get('tcp_timeout',4.0))))
            safe_cap=max(2,min(base,profile['cpu_count']*2,int(max(2,ram_gb)*2),32))
            self.settings.data['max_workers']=safe_cap
            if plan in ('light','balanced','intensive'): self.settings.data['tcp_timeout']=plan_timeout
        self.settings.data['hardware_profile']=profile; self.settings.save(); self.hardware_profile=profile
    def update_performance(self):
        cpu_text='Недоступно'; ram_text='Недоступно'; disk_text='Недоступно'
        try:
            import psutil
            cpu_text=f'{psutil.cpu_percent(interval=None):.0f}%'
            mem=psutil.virtual_memory(); ram_text=f'{mem.percent:.0f}% · {mem.used/1024**3:.1f}/{mem.total/1024**3:.1f} ГБ'
            disk=psutil.disk_usage(str(self.data_dir)); disk_text=f'{disk.free/1024**3:.1f} ГБ свободно'
        except Exception as exc:
            # Native Windows memory fallback; disk and CPU count do not require psutil.
            try:
                import ctypes
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_=[('dwLength',ctypes.c_ulong),('dwMemoryLoad',ctypes.c_ulong),('ullTotalPhys',ctypes.c_ulonglong),('ullAvailPhys',ctypes.c_ulonglong),('ullTotalPageFile',ctypes.c_ulonglong),('ullAvailPageFile',ctypes.c_ulonglong),('ullTotalVirtual',ctypes.c_ulonglong),('ullAvailVirtual',ctypes.c_ulonglong),('ullAvailExtendedVirtual',ctypes.c_ulonglong)]
                m=MEMORYSTATUSEX(); m.dwLength=ctypes.sizeof(m)
                if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
                    used=m.ullTotalPhys-m.ullAvailPhys
                    ram_text=f'{m.dwMemoryLoad}% · {used/1024**3:.1f}/{m.ullTotalPhys/1024**3:.1f} ГБ'
            except Exception: pass
            try:
                import shutil
                d=shutil.disk_usage(str(self.data_dir)); disk_text=f'{d.free/1024**3:.1f} ГБ свободно'
            except Exception: pass
            cpu_text=f'{os.cpu_count() or 1} логич. CPU · psutil недоступен'
        if not hasattr(self,'performance_labels'): return
        self.performance_labels['cpu'].setText(cpu_text)
        self.performance_labels['ram'].setText(ram_text)
        self.performance_labels['disk'].setText(disk_text)
        self.performance_labels['workers'].setText(f"{self.settings.data['max_workers']} · профиль {self.settings.data.get('performance_plan','не выбран')}")
        hp=getattr(self,'hardware_profile',{})
        self.performance_labels['hardware'].setText(f"{hp.get('cpu_count',os.cpu_count() or '?')} CPU · {hp.get('ram_gb','?')} ГБ RAM")
    def update_component_info(self):
        path=Path(self.settings.data.get('singbox_path') or '')
        if not path.is_file():
            candidate=self.data_dir/'components'/'sing-box'
            found=None
            if candidate.exists():
                for folder in candidate.glob('sing-box-*'):
                    if (folder/'sing-box.exe').is_file():found=folder/'sing-box.exe'; break
            path=found if found else path
        if path.is_file():self.component_info.setText(f'Установлен: {path}\nИсточник: официальный релиз SagerNet/sing-box')
        else:self.component_info.setText('sing-box пока не установлен. Его можно загрузить кнопкой ниже.')
    def check_component_update(self):
        def work():
            from .components import latest_singbox_release,installed_version
            release=latest_singbox_release(); current=self.settings.data.get('singbox_path','')
            version=installed_version(current) if current else 'не установлен'
            return release,version
        self.run_job(work,self.finish_component_check)
    def finish_component_check(self,result):
        ok,payload=result
        if not ok:
            self.component_info.setText(f'Не удалось проверить релиз: {payload}'); return
        release,current=payload
        self.component_info.setText(f"Последний стабильный релиз: {release['version']}\nУстановленная версия: {current}\nАрхив: {release['asset_name']}\nSHA-256 опубликован GitHub.")
        self._latest_component_release=release
    def install_component(self):
        if QMessageBox.question(self,'Установка sing-box','Загрузить стабильный архив sing-box с официального GitHub SagerNet, проверить SHA-256 и сохранить локально? Программа не будет запускать VPN.')!=QMessageBox.Yes:return
        def work():
            from .components import latest_singbox_release,install_singbox
            release=latest_singbox_release(); path=install_singbox(self.data_dir/'components'/'sing-box',release)
            return release,path
        self.run_job(work,self.finish_component_install)
    def finish_component_install(self,result):
        ok,payload=result
        if not ok:
            self.component_info.setText(f'Установка не выполнена: {payload}'); self.db.add_event(f'Установка sing-box не выполнена: {payload}','ERROR'); return
        release,path=payload; self.settings.data['singbox_path']=str(path); self.settings.save()
        self.component_info.setText(f"Установлен sing-box {release['version']}\n{path}\nSHA-256 проверен.")
        self.db.add_event(f"Установлен официальный sing-box {release['version']}"); self.refresh_all()

    def update_quality(self):
        if not hasattr(self,'quality_summary'):return
        stats=self.db.stats(); imports=self.db.rows('imports',200)
        error_count=sum(r['errors'] for r in imports); duplicate_count=sum(r['skipped'] for r in imports)
        self.quality_summary.setText(f"Всего конфигураций: {stats['configs']}\nНе проверено: {stats['unchecked']}\nПоследняя проверка неуспешна: {stats['unreachable']}\nОшибок разбора в последних 200 импортов: {error_count}\nПропущено повторов при импорте: {duplicate_count}\n\nОригинальные файлы не изменяются. Повреждённые или неоднозначные записи не исправляются автоматически.")
        self.import_table.setRowCount(0)
        for r in imports:self.add_row(self.import_table,[r['created_at'],r['filename'],r['added'],r['skipped'],r['errors']])

    def update_analytics(self):
        if not hasattr(self,'analytics_text'):return
        stats=self.db.stats(); ratings=getattr(self,'_ratings',None)
        if ratings is None:ratings=self.db.source_ratings()
        notes=[]
        notes.append(f"Каталог: {stats['configs']} конфигураций; TCP доступен: {stats['reachable']}; недоступен: {stats['unreachable']}; не проверено: {stats['unchecked']}.")
        if stats['configs'] and stats['unchecked']>stats['configs']*0.5: notes.append('Более половины записей ещё не проверялись. Запусти обычную или энергосберегающую проверку.')
        if stats['unreachable']>stats['reachable']: notes.append('Недоступных TCP-адресов больше, чем доступных. Это не доказывает, что протоколы не работают: проверь позже и сравни историю.')
        if ratings:
            best=ratings[0]; notes.append(f"Лучший источник по текущей мягкой оценке: {best['url']} — {best['rating']:.1f}/100 ({best['samples']} проверок).")
            weak=[x for x in ratings if x['rating']<40 and x['samples']>=5]
            if weak: notes.append(f"Есть {len(weak)} источников с низкой оценкой и достаточной историей. Проверь их вручную перед отключением.")
        else: notes.append('Источники ещё не добавлены.')
        notes.append('Рейтинг ориентировочный: временные отказы и небольшая выборка сглаживаются. Он не гарантирует качество или безопасность конфигурации.')
        self.analytics_text.setPlainText('\n\n'.join(notes))
    def run_diagnostics(self):
        checks=[]
        checks.append(('База данных',self.db.integrity_check()))
        checks.append(('Каталог данных','доступен' if self.data_dir.is_dir() and os.access(self.data_dir,os.W_OK) else 'нет доступа на запись'))
        checks.append(('Резервные копии','доступны' if (self.data_dir/'backups').exists() else 'папка будет создана при первом резервировании'))
        self.diag_label.setText('\n'.join(f'{name}: {value}' for name,value in checks))
        level='INFO' if all(v=='ok' or v=='доступен' or v.startswith('папка') for _,v in checks) else 'WARN'
        self.db.add_event('Самодиагностика выполнена: '+ '; '.join(f'{a}={b}' for a,b in checks),level); self.refresh_all()
    def create_backup(self):
        try:
            path=self.data_dir/'backups'/f"vpndesk_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.sqlite"; self.db.backup(path)
            self.log(f'Резервная копия создана: {path.name}'); return True
        except Exception as exc: QMessageBox.critical(self,'Ошибка резервирования',str(exc)); return False
    def check_integrity(self):
        result=self.db.integrity_check(); self.maintenance_info.setText(f'Результат PRAGMA integrity_check: {result}')
        self.db.add_event(f'Проверка целостности БД: {result}','INFO' if result=='ok' else 'ERROR'); self.refresh_all()
    def smart_cleanup(self):
        with self.db.lock:
            rows=self.db.conn.execute("SELECT id,protocol,host,port,last_checked FROM configs WHERE status='unreachable' AND last_checked<>'' AND last_checked<? ORDER BY last_checked",((datetime.now(timezone.utc)-timedelta(days=30)).isoformat(timespec='seconds'),)).fetchall()
        if not rows:
            QMessageBox.information(self,'Очистка','Нет недоступных записей старше 30 дней.'); return
        preview='\n'.join(f"#{r['id']} {r['protocol']}://{r['host']}:{r['port']} · {r['last_checked']}" for r in rows[:30])
        if len(rows)>30:preview+=f'\n… и ещё {len(rows)-30}'
        if QMessageBox.question(self,'Предпросмотр очистки',f'Найдено {len(rows)} записей, недоступных более 30 дней. Удалить их?\n\n{preview}')!=QMessageBox.Yes:return
        if not self.create_backup():return
        with self.db.lock,self.db.conn:self.db.conn.executemany('DELETE FROM configs WHERE id=?',[(r['id'],) for r in rows])
        self.log(f'Умная очистка: удалено {len(rows)} старых недоступных записей')

    def show_page(self,name): self.stack.setCurrentWidget(self.pages[name][0]); self.refresh_all()
    def apply_theme(self): QApplication.instance().setStyleSheet(DARK if self.settings.data['theme']=='dark' else LIGHT)
    def refresh_all(self):
        s=self.db.stats()
        for k,label in self.stat_labels.items(): label.setText(str(s.get(k,0)))
        ratings=self.db.source_ratings(); self._ratings=ratings
        self.source_table.setRowCount(0)
        for r in ratings:
            vals=[r['id'],r['url'],r['status'],f"{r['rating']:.1f}/100",r['configs_total'],r['configs_reachable'],r['failures'],r['last_checked'] or '—']
            self.add_row(self.source_table,vals)
        self.config_table.setRowCount(0)
        config_rows=self.db.rows('configs',500)
        with self.db.lock:
            check_types={r['config_id']:r['check_kind'] for r in self.db.conn.execute('SELECT config_id,check_kind FROM config_checks ORDER BY id').fetchall()}
        metrics=self.db.config_metrics([r['id'] for r in config_rows])
        config_rows=sorted(config_rows,key=lambda r:metrics.get(r['id'],{}).get('quality',0),reverse=True)
        for r in config_rows:
            m=metrics.get(r['id'],{})
            vals=[r['id'],r['protocol'],r['host'],r['port'],classify_transport(r['protocol']),r['status'],r['latency_ms'] if r['latency_ms'] is not None else '—',f"{m.get('stability','—')}%" if m else '—',m.get('quality','—'),check_types.get(r['id'],'—')]
            self.add_row(self.config_table,vals)
        self.log_table.setRowCount(0)
        for r in self.db.rows('events',200): self.add_row(self.log_table,[r['created_at'],r['level'],r['message']])
        recent=self.db.rows('events',15); self.recent.setPlainText('\n'.join(f"{x['created_at'][11:19]} [{x['level']}] {x['message']}" for x in reversed(recent)))
        latencies=[r['latency_ms'] for r in self.db.rows('config_checks',250) if r['latency_ms'] is not None]
        self.charts.set_data(s['configs'],s['reachable'],s['unreachable'],latencies)
        self.source_tree.clear()
        with self.db.lock:
            links=self.db.conn.execute('''SELECT cs.source_id,c.id,c.protocol,c.host,c.port,c.status
                FROM config_sources cs JOIN configs c ON c.id=cs.config_id ORDER BY cs.source_id,c.id LIMIT 2000''').fetchall()
        by_source={}
        for item in links: by_source.setdefault(item['source_id'],[]).append(item)
        for src in ratings:
            root=QTreeWidgetItem([src['url'],src['status'],f"Рейтинг {src['rating']:.1f} · {src['configs_total']} записей"])
            self.source_tree.addTopLevelItem(root)
            for c in by_source.get(src['id'],[])[:500]:
                root.addChild(QTreeWidgetItem([f"#{c['id']} {c['protocol']}://{c['host']}:{c['port']}",c['status'],c['protocol'].upper()]))
        self.source_tree.expandToDepth(0)
        self.update_quality(); self.update_analytics()
    def add_row(self,t,vals):
        r=t.rowCount(); t.insertRow(r)
        for c,v in enumerate(vals): t.setItem(r,c,QTableWidgetItem(str(v if v is not None else '')))
    def selected_id(self,table):
        rows=table.selectionModel().selectedRows(); return int(table.item(rows[0].row(),0).text()) if rows else None
    def log(self,msg,level='INFO'):
        self.db.add_event(msg,level); self.refresh_all(); self.status_label.setText(msg)
    def import_items(self,items,errors,filename,digest=''):
        dialog=PreviewDialog(self,items,errors)
        if dialog.exec()!=QDialog.Accepted: self.log(f'Импорт отменён: {filename}'); return
        if dialog.test_sources and dialog.test_sources.isChecked():
            sources=[x for x in items if x.kind=='source']
            if sources:
                self._pending_source_import=(items,errors,filename,digest)
                timeout=int(self.settings.data.get('source_timeout',12)); max_mb=int(self.settings.data.get('source_max_mb',32))
                def test_sources(job):
                    tested=[]
                    for index,item in enumerate(sources,1):
                        if job.cancel_event.is_set(): raise CheckCancelled('Предварительный тест источников отменён', tested)
                        started=time.perf_counter()
                        try: tested.append((item,True,fetch_source(item.value,timeout,max_mb),(time.perf_counter()-started)*1000))
                        except Exception as exc: tested.append((item,False,str(exc),(time.perf_counter()-started)*1000))
                        job.progress.emit(index,len(sources),{'source':item.value})
                    return tested
                self.status_label.setText(f'Предварительная проверка {len(sources)} URL-источников…')
                self.run_job(test_sources,self.finish_preimport_sources,cancellable=True)
                return
        try:
            self.db.backup(self.data_dir/'backups'/f'vpndesk_{datetime.now().strftime("%Y%m%d_%H%M%S_%f")}.sqlite')
        except Exception as exc:
            QMessageBox.critical(self,'Резервная копия не создана',f'Импорт отменён, потому что не удалось создать резервную копию базы: {exc}'); return
        try:
            added,skipped=self.db.import_batch(items,filename,digest,len(errors))
        except Exception as exc:
            self.db.add_event(f'Импорт {filename} отменён: транзакция откатилась ({exc})','ERROR')
            QMessageBox.critical(self,'Импорт не выполнен','База не была изменена: операция целиком отменена.\n'+str(exc)); self.refresh_all(); return
        self.log(f'Импорт {filename}: добавлено {added}, дубликатов {skipped}, ошибок {len(errors)}')
    def finish_preimport_sources(self,result):
        ok,payload=result
        if not ok:
            QMessageBox.warning(self,'Тест источников не выполнен',str(payload)); return
        items,errors,filename,digest=self._pending_source_import
        successful=[]; discovered=[]; failed=[]
        for source,success,value,elapsed in payload:
            if success:
                successful.append(source)
                found,bad=value; discovered.extend(x for x in found if x.kind=='config')
            else: failed.append((source.value,str(value)))
        summary=f'Успешно: {len(successful)} из {len(payload)}\nНайдено новых конфигураций: {len(discovered)}\nОшибок: {len(failed)}'
        if failed: summary+='\n\nПервые ошибки:\n'+'\n'.join(f'{u}: {e[:120]}' for u,e in failed[:8])
        if QMessageBox.question(self,'Результаты предварительного теста',summary+'\n\nИмпортировать успешные источники и найденные конфигурации?')!=QMessageBox.Yes:
            self.db.add_event('Импорт после предварительного теста отменён'); return
        try:
            self.db.backup(self.data_dir/'backups'/f'vpndesk_{datetime.now().strftime("%Y%m%d_%H%M%S_%f")}.sqlite')
            # Preserve non-source records from the pasted text, and only keep URLs that passed the test.
            selected=[x for x in items if x.kind!='source']+successful
            added,skipped=self.db.import_batch(selected,filename,digest,len(errors)+len(failed))
            for source,success,value,elapsed in payload:
                if not success: continue
                sid=next((r['id'] for r in self.db.rows('sources',10000) if r['url']==source.value),None)
                if sid:
                    found,_=value
                    for item in found:
                        if item.kind=='config': self.db.add_config(item,sid)
                    self.db.record_source_result(sid,True,configs_found=sum(1 for x in found if x.kind=='config'),elapsed_ms=elapsed)
            self.log(f'Предварительный тест завершён: добавлено {added+len(discovered)}; не прошли тест {len(failed)}')
        except Exception as exc:
            QMessageBox.critical(self,'Импорт не выполнен',str(exc)); self.db.add_event(f'Ошибка импорта после теста: {exc}','ERROR')
        self.refresh_all()

    def preview_paste(self):
        text=self.paste.toPlainText()
        if not text.strip(): QMessageBox.information(self,'Пустой ввод','Сначала вставь текст.'); return
        items,errors=read_pasted(text); self.import_items(items,errors,'Буфер обмена',hashlib.sha256(text.encode()).hexdigest())
    def paste_text(self): self.show_page('Импорт'); self.paste.setFocus()
    def pick_files(self,zip_only=False):
        filt='ZIP архив (*.zip)' if zip_only else 'Поддерживаемые файлы (*.txt *.json *.yaml *.yml *.csv *.conf *.list *.zip);;Все файлы (*.*)'
        paths,_=QFileDialog.getOpenFileNames(self,'Выбрать файлы','',filt)
        if not paths:return
        max_mb=self.settings.data['max_file_mb']; max_zip=self.settings.data['max_archive_unpacked_mb']
        def read_batch():
            results=[]
            for name in paths:
                try: results.append((name,True,read_file(Path(name),max_mb,max_zip)))
                except Exception as exc: results.append((name,False,str(exc)))
            return results
        self.run_job(read_batch,self.finish_file_batch)
    def finish_file_batch(self,result):
        ok,payload=result
        if not ok:
            self.log(f'Не удалось обработать выбранные файлы: {payload}','ERROR'); return
        for name,success,value in payload:
            if success:
                items,errors,digest=value
                self.import_items(items,errors,Path(name).name,digest)
            else:
                QMessageBox.warning(self,'Не удалось импортировать',f'{Path(name).name}\n{value}')
                self.log(f'Ошибка импорта {Path(name).name}: {value}','ERROR')
    def add_source_dialog(self):
        from PySide6.QtWidgets import QInputDialog
        url,ok=QInputDialog.getText(self,'Добавить источник','URL (HTTP или HTTPS):')
        if ok and url.strip():
            if not url.strip().lower().startswith(('http://','https://')): QMessageBox.warning(self,'Неверный URL','Разрешены только HTTP и HTTPS.'); return
            _,new=self.db.add_source(url.strip()); self.log('Источник добавлен' if new else 'Такой источник уже существует')
    def check_all_sources(self):
        rows=[r for r in self.db.rows('sources',10000) if r['status']=='active']
        if not rows: QMessageBox.information(self,'Нет активных источников','Добавь URL-источники или верни источник из карантина.'); return
        if QMessageBox.question(self,'Проверить источники',f'Проверить {len(rows)} активных источников?')!=QMessageBox.Yes:return
        source_timeout=int(self.settings.data['source_timeout']); source_max=int(self.settings.data['source_max_mb'])
        def work():
            result=[]
            for row in rows:
                started=time.perf_counter()
                try: result.append((row['id'],True,fetch_source(row['url'],source_timeout,source_max), (time.perf_counter()-started)*1000))
                except Exception as exc: result.append((row['id'],False,exc, (time.perf_counter()-started)*1000))
            return result
        self.run_job(work,self.finish_all_sources)
    def finish_all_sources(self,result):
        ok,payload=result
        if not ok: self.log(f'Сбор источников завершился ошибкой: {payload}','ERROR'); return
        total_added=failures=0
        for sid,success,value,elapsed_ms in payload:
            if success:
                items,errors=value; count=0
                for item in items:
                    if item.kind=='config': count+=int(self.db.add_config(item,sid))
                    elif item.kind=='source': self.db.add_source(item.value)
                total_added+=count
                self.db.record_source_result(sid,True,configs_found=count,elapsed_ms=elapsed_ms)
            else:
                code=getattr(value,'code',None); transient=bool(code==429 or (code is not None and 500<=code<=599))
                self.db.record_source_result(sid,False,str(value),error_type=f'HTTP {code}' if code else type(value).__name__,http_code=code,elapsed_ms=elapsed_ms,transient=transient)
                if transient:self.db.add_event(f'Временная ошибка источника ({code or type(value).__name__}); счётчик карантина не увеличен','WARN')
                else:failures+=1
        self.log(f'Обход источников завершён: новых конфигураций {total_added}, ошибок {failures}')
        QTimer.singleShot(250,self.publish_report)
    def check_selected_source(self):
        sid=self.selected_id(self.source_table)
        if not sid: QMessageBox.information(self,'Источник не выбран','Выбери источник в таблице.'); return
        row=next((x for x in self.db.rows('sources',10000) if x['id']==sid),None)
        if not row:return
        timeout=int(self.settings.data['source_timeout']); max_mb=int(self.settings.data['source_max_mb'])
        def fetch_one():
            started=time.perf_counter()
            try:return True,fetch_source(row['url'],timeout,max_mb),(time.perf_counter()-started)*1000
            except Exception as exc:return False,exc,(time.perf_counter()-started)*1000
        self.run_job(fetch_one,lambda result:self.finish_source(sid,result))
    def finish_source(self,sid,result):
        ok,payload=result
        if not ok:return self.log(f'Ошибка фоновой задачи источника: {payload}','ERROR')
        success,value,elapsed_ms=payload
        if success:
            items,errors=value; added=0
            for item in items:
                if item.kind=='config': added+=int(self.db.add_config(item,sid))
                elif item.kind=='source': self.db.add_source(item.value)
            self.db.record_source_result(sid,True,configs_found=added,elapsed_ms=elapsed_ms)
            self.log(f'Источник обработан: новых конфигураций {added}, ошибок разбора {len(errors)}'); QTimer.singleShot(250,self.publish_report)
        else:
            exc=value; code=getattr(exc,'code',None); transient=bool(code==429 or (code is not None and 500<=code<=599))
            self.db.record_source_result(sid,False,str(exc),error_type=f'HTTP {code}' if code else type(exc).__name__,http_code=code,elapsed_ms=elapsed_ms,transient=transient)
            self.log(f'Ошибка источника: {exc}'+(' (временная, карантин не увеличен)' if transient else ''),'WARN')
    def edit_source(self):
        sid=self.selected_id(self.source_table)
        if not sid: QMessageBox.information(self,'Источник не выбран','Выбери источник.'); return
        row=next((x for x in self.db.rows('sources',10000) if x['id']==sid),None)
        if not row:return
        url,ok=QInputDialog.getText(self,'Изменить источник','Новый URL:',text=row['url'])
        if not ok:return
        url=url.strip()
        if not url.lower().startswith(('http://','https://')):
            QMessageBox.warning(self,'Неверный URL','Разрешены только HTTP и HTTPS.'); return
        try:
            self.db.update_source(sid,url); self.log('URL источника обновлён')
        except Exception as exc: QMessageBox.warning(self,'Не удалось изменить источник',str(exc))
    def toggle_source(self):
        sid=self.selected_id(self.source_table)
        if not sid: QMessageBox.information(self,'Источник не выбран','Выбери источник.'); return
        row=next((x for x in self.db.rows('sources',10000) if x['id']==sid),None)
        if not row:return
        enabled=not bool(row['enabled'])
        self.db.set_source_enabled(sid,enabled); self.log('Источник включён' if enabled else 'Источник отключён')
    def delete_source(self):
        selected=sorted({x.row() for x in self.source_table.selectionModel().selectedRows()})
        ids=[int(self.source_table.item(r,0).text()) for r in selected]
        if not ids: QMessageBox.information(self,'Источник не выбран','Выбери один или несколько источников.'); return
        if QMessageBox.question(self,'Удалить источники',f'Удалить {len(ids)} URL и их связи с конфигурациями? Сами конфигурации останутся в каталоге.')!=QMessageBox.Yes:return
        if not self.create_backup():return
        for sid in ids:self.db.delete_source(sid)
        self.log(f'Удалено источников: {len(ids)}; конфигурации сохранены')

    def restore_source(self):
        sid=self.selected_id(self.source_table)
        if not sid: QMessageBox.information(self,'Не выбран','Выбери источник.'); return
        if QMessageBox.question(self,'Вернуть источник','Вернуть источник в активные и сбросить счётчик ошибок?')==QMessageBox.Yes:
            with self.db.lock,self.db.conn: self.db.conn.execute("UPDATE sources SET status='active',enabled=1,failures=0,last_error='' WHERE id=?",(sid,))
            self.log('Источник возвращён в активные')
    def run_job(self,fn,callback,cancellable=False):
        if self.job and self.job.isRunning(): QMessageBox.information(self,'Задача выполняется','Сначала заверши или останови текущую операцию.'); return
        self.progress.setRange(0,0); self.progress.setValue(0); self.progress.show()
        job=Job(fn if cancellable else (lambda _job: fn()))
        self.job=job; job.done.connect(lambda result:setattr(job,'_result',result))
        job.progress.connect(self.on_job_progress)
        job.finished.connect(lambda:self.finish_job(job,callback))
        self.pause_btn.setEnabled(cancellable); self.stop_btn.setEnabled(cancellable)
        job.start()
    def on_job_progress(self,current,total,detail):
        self.progress.setRange(0,max(1,total)); self.progress.setValue(current)
        self.status_label.setText(f'Проверка: {current} из {total}')
    def finish_job(self,job,callback):
        if self._closing:return
        result=getattr(job,'_result',(False,RuntimeError('Задача завершилась без результата')))
        self.progress.hide(); self.pause_btn.setEnabled(False); self.stop_btn.setEnabled(False); self.pause_btn.setText('Ⅱ Пауза')
        if self.job is job:self.job=None
        callback(result)
    def pause_job(self):
        if not self.job or not self.job.isRunning():return
        paused=self.job.toggle_pause(); self.pause_btn.setText('▶ Продолжить' if paused else 'Ⅱ Пауза')
        self.status_label.setText('Проверка приостановлена' if paused else 'Проверка продолжена')
    def stop_job(self):
        if self.job and self.job.isRunning():
            self.job.cancel(); self.status_label.setText('Останавливаю проверку и сохраняю завершённые результаты…')
    def check_configs(self):
        energy=bool(self.settings.data.get('energy_saving_enabled'))
        rows=self.db.select_energy_configs(int(self.settings.data['energy_check_limit'])) if energy else self.db.rows('configs',1000000)
        tcp=[r for r in rows if classify_transport(r['protocol'])=='TCP']
        if not tcp: QMessageBox.information(self,'Нет TCP-конфигураций','Для TCP-проверки пока нет записей. UDP-протоколы не помечаются как проверенные.'); return
        mode='Энергосберегающий режим' if energy else 'Обычный режим'
        if QMessageBox.question(self,'Проверить доступность',f'{mode}: проверить адреса и TCP-порты у {len(tcp)} записей? Это только быстрая TCP-проверка; она не подтверждает работу VPN-протокола.')!=QMessageBox.Yes:return
        timeout=min(float(self.settings.data['tcp_timeout']),float(self.settings.data.get('energy_timeout',1.5))) if energy else float(self.settings.data['tcp_timeout'])
        workers=min(int(self.settings.data['max_workers']),4) if energy else int(self.settings.data['max_workers'])
        def work(job):
            return run_tcp_checks(tcp,timeout=timeout,max_workers=workers,cancel_event=job.cancel_event,
                pause_event=job.pause_event,progress=job.progress.emit)
        self.run_job(work,self.finish_checks,cancellable=True)
    def check_protocol_configs(self):
        binary=self.settings.data.get('singbox_path','')
        if not binary or not Path(binary).is_file():
            QMessageBox.information(self,'Нужен sing-box','Сначала открой раздел «Компоненты» и установи официальный sing-box. После этого появится полноценная протокольная проверка.')
            self.show_page('Компоненты'); return
        selected=sorted({x.row() for x in self.config_table.selectionModel().selectedRows()})
        if selected:
            ids={int(self.config_table.item(r,0).text()) for r in selected}
            rows=[r for r in self.db.rows('configs',1000000) if r['id'] in ids]
        else:
            rows=self.db.rows('configs',1000000)
        if self.settings.data.get('energy_saving_enabled') and not selected:
            ids={r['id'] for r in self.db.select_energy_configs(int(self.settings.data['energy_check_limit']))}
            rows=[r for r in rows if r['id'] in ids]
        if not rows:
            QMessageBox.information(self,'Нет записей','Сначала импортируй конфигурации или выбери строки в каталоге.'); return
        if QMessageBox.question(self,'Полная VPN-проверка',
            f'Проверить {len(rows)} конфигураций через sing-box?\n\n'
            'Для каждой записи будет запущен отдельный ограниченный локальный тестовый процесс. Он проверит реальный протокольный выход к тестовому HTTPS-адресу через локальный SOCKS-прокси. Системные маршруты и DNS Windows не меняются.\n'
            'Проверка использует трафик и может быть медленнее TCP-проверки.')!=QMessageBox.Yes:return
        from .checker import run_singbox_checks
        timeout=float(self.settings.data.get('protocol_timeout',10))
        workers=max(1,min(int(self.settings.data.get('max_workers',8)),4 if self.settings.data.get('energy_saving_enabled') else 8))
        def work(job):
            return run_singbox_checks(rows,binary,timeout=timeout,max_workers=workers,
                cancel_event=job.cancel_event,pause_event=job.pause_event,progress=job.progress.emit)
        self.run_job(work,self.finish_protocol_checks,cancellable=True)

    def finish_protocol_checks(self,result):
        ok,payload=result
        if not ok:
            if isinstance(payload,CheckCancelled):
                results=payload.results
                for cid,status,latency,error in results:self.db.update_config_result(cid,status,latency,error,'sing-box')
                self.db.add_event(f'Полная проверка остановлена; сохранено результатов: {len(results)}','WARN')
            else:self.db.add_event(f'Полная проверка завершилась ошибкой: {payload}','ERROR')
            self.refresh_all(); return
        for cid,status,latency,error in payload:self.db.update_config_result(cid,status,latency,error,'sing-box')
        good=sum(1 for x in payload if x[1]=='reachable')
        self.db.add_event(f'Полная проверка sing-box: успешно {good} из {len(payload)}; проверялся реальный HTTPS-выход через конфигурации')
        self.refresh_all(); QTimer.singleShot(250,self.publish_report)

    def finish_checks(self,result):
        ok,payload=result
        if not ok:
            if isinstance(payload,CheckCancelled):
                payload_results=payload.results
                for cid,status,latency,error in payload_results:self.db.update_config_result(cid,status,latency,error,'tcp')
                self.log(f'Проверка отменена; сохранено результатов: {len(payload_results)}','WARN'); self.refresh_all()
            else:self.log(f'Проверка завершилась ошибкой: {payload}','ERROR')
            return
        for cid,status,latency,error in payload:self.db.update_config_result(cid,status,latency,error,'tcp')
        good=sum(1 for x in payload if x[1]=='reachable'); self.log(f'TCP-проверка завершена: доступно {good} из {len(payload)}; протокольные рукопожатия не выполнялись'); self.refresh_all(); QTimer.singleShot(250,self.publish_report)
    def show_config_history(self):
        cid=self.selected_id(self.config_table)
        if not cid:QMessageBox.information(self,'Конфигурация не выбрана','Выбери запись в таблице.'); return
        rows=self.db.config_history(cid,200)
        dlg=QDialog(self); dlg.setWindowTitle(f'История конфигурации #{cid}'); dlg.resize(760,460); layout=QVBoxLayout(dlg)
        table=self.make_table(['Дата проверки','Результат','Задержка, мс','Тип проверки','Ошибка'])
        for r in rows:self.add_row(table,[r['checked_at'],r['status'],r['latency_ms'] if r['latency_ms'] is not None else '—',r['check_kind'],r['error']])
        layout.addWidget(table); close=QPushButton('Закрыть'); close.clicked.connect(dlg.accept); layout.addWidget(close); dlg.exec()

    def export_configs(self):
        path,_=QFileDialog.getSaveFileName(self,'Экспорт конфигураций','vpndesk-configs.txt','TXT (*.txt)')
        if not path:return
        rows=self.db.rows('configs',100000)
        # Explicit user action; exported configs may contain credentials.
        Path(path).write_text('\n'.join(r['uri'] for r in rows),encoding='utf-8')
        self.log(f'Экспортировано записей: {len(rows)}')
    def delete_configs(self):
        ids=[int(self.config_table.item(r,0).text()) for r in sorted({x.row() for x in self.config_table.selectionModel().selectedRows()})]
        if not ids: QMessageBox.information(self,'Нет выбора','Выбери конфигурации.'); return
        if QMessageBox.question(self,'Удалить записи',f'Удалить выбранные конфигурации ({len(ids)})?')==QMessageBox.Yes:
            if not self.create_backup():return
            with self.db.lock,self.db.conn:self.db.conn.executemany('DELETE FROM configs WHERE id=?',[(x,) for x in ids])
            self.log(f'Удалено конфигураций: {len(ids)}')
    def clear_logs(self):
        if QMessageBox.question(self,'Очистить журнал','Удалить всю историю событий?')==QMessageBox.Yes:
            with self.db.lock,self.db.conn:self.db.conn.execute('DELETE FROM events')
            self.refresh_all()
    def publish_report(self):
        from .reporter import sanitized_report
        stats=self.db.stats(); reports=self.data_dir/'reports'; reports.mkdir(exist_ok=True)
        try:
            (reports/'latest-stats.json').write_text(json.dumps(sanitized_report(stats),ensure_ascii=False,indent=2),encoding='utf-8')
        except OSError as exc: self.db.add_event(f'Не удалось сохранить локальный отчёт: {exc}','ERROR')
        token=get_token()
        if self.settings.data.get('github_auto') and self.settings.data.get('github_repo') and token:
            github_settings=dict(self.settings.data); github_settings['github_token']=token
            self.run_job(lambda:publish_github(github_settings,stats),self.finish_publish)
    def finish_publish(self,result):
        ok,payload=result
        if ok and payload[0]: self.db.add_event('Очищенная статистика опубликована на GitHub')
        elif ok: self.db.add_event(payload[1],'WARN')
        else: self.db.add_event(f'Ошибка публикации: {payload}','WARN')
        self.refresh_all()
    def open_settings(self):
        old_portable=bool(self.settings.data.get('portable_mode'))
        dlg=SettingsDialog(self,self.settings)
        if dlg.exec()==QDialog.Accepted:
            new_portable=bool(self.settings.data.get('portable_mode'))
            if old_portable!=new_portable and not self.switch_portable_mode(new_portable):
                self.settings.data['portable_mode']=old_portable; self.settings.save()
            self.apply_theme(); self.db.add_event('Настройки обновлены'); self.refresh_all(); self.update_analytics()
            if not self.settings.data['tray_enabled'] and self.tray:
                self.tray.hide(); self.tray=None
            elif self.settings.data['tray_enabled'] and not self.tray and QSystemTrayIcon.isSystemTrayAvailable():
                self.tray=QSystemTrayIcon(self); self.tray.setToolTip('VPNDesk'); menu=QMenu(); a=menu.addAction('Открыть VPNDesk'); a.triggered.connect(self.showNormal); q=menu.addAction('Выход'); q.triggered.connect(self.exit_app); self.tray.setContextMenu(menu); self.tray.activated.connect(lambda reason:self.showNormal() if reason==QSystemTrayIcon.DoubleClick else None); self.tray.show()
            if self.settings.data['github_auto'] and self.settings.data['github_repo'] and get_token():
                self.status_label.setText('Автопубликация GitHub настроена: будет отправляться только очищенная статистика.')
    def switch_portable_mode(self,enabled):
        try:
            from .app import portable_marker_path,portable_data_dir,local_data_dir
            target=portable_data_dir() if enabled else local_data_dir()
            marker=portable_marker_path()
            if target.resolve()==self.data_dir.resolve():return True
            if (target/'vpndesk.db').exists():
                QMessageBox.warning(self,'Переключение не выполнено',f'В целевой папке уже есть база: {target}. Чтобы не перезаписать данные, переключение отменено.')
                return False
            shutil.copytree(self.data_dir,target,dirs_exist_ok=True)
            if enabled:marker.write_text('VPNDesk portable data\n',encoding='utf-8')
            elif marker.exists():marker.unlink()
            QMessageBox.information(self,'Портативный режим изменён',f'Данные скопированы в:\n{target}\nПерезапусти VPNDesk, чтобы применить новый путь.')
            return True
        except Exception as exc:
            QMessageBox.critical(self,'Не удалось переключить режим',str(exc)); return False
    def run_shutdown_check(self):
        if platform.system()!='Windows':
            self.db.add_event('Автовыключение поддерживается только в Windows','WARN'); return
        rows=self.db.select_energy_configs(int(self.settings.data['energy_check_limit'])) if self.settings.data.get('energy_saving_enabled') else self.db.rows('configs',1000000)
        tcp=[r for r in rows if classify_transport(r['protocol'])=='TCP']
        if not tcp:
            self.db.add_event('Финальная проверка не выполнена: нет TCP-конфигураций; компьютер не выключен','WARN'); self.refresh_all(); return
        self.db.add_event(f'Запущена финальная проверка перед выключением: {len(tcp)} записей')
        timeout=min(float(self.settings.data['tcp_timeout']),float(self.settings.data.get('energy_timeout',1.5))) if self.settings.data.get('energy_saving_enabled') else float(self.settings.data['tcp_timeout'])
        workers=min(int(self.settings.data['max_workers']),4) if self.settings.data.get('energy_saving_enabled') else int(self.settings.data['max_workers'])
        def work(job):
            return run_tcp_checks(tcp,timeout=timeout,max_workers=workers,cancel_event=job.cancel_event,pause_event=job.pause_event,progress=job.progress.emit)
        self.run_job(work,self.finish_shutdown_checks,cancellable=True)
    def finish_shutdown_checks(self,result):
        ok,payload=result
        if not ok:
            if isinstance(payload,CheckCancelled):
                for cid,status,latency,error in payload.results:self.db.update_config_result(cid,status,latency,error,'tcp')
                self.db.add_event(f'Финальная проверка отменена; сохранено {len(payload.results)} результатов; выключение отменено','WARN')
            else:self.db.add_event(f'Финальная проверка не завершена: {payload}; выключение отменено','WARN')
            self.refresh_all(); return
        for cid,status,latency,error in payload:self.db.update_config_result(cid,status,latency,error,'tcp')
        good=sum(1 for x in payload if x[1]=='reachable')
        self.db.add_event(f'Финальная проверка сохранена: TCP доступен у {good} из {len(payload)} записей')
        self.refresh_all(); self.publish_report()
        if QMessageBox.question(self,'Финальная проверка завершена',f'Результаты сохранены. Выключить компьютер через 60 секунд?\nПроверено: {len(payload)}, TCP доступен: {good}.')!=QMessageBox.Yes:
            self.db.add_event('Автовыключение отменено пользователем','INFO'); return
        try:
            flags=getattr(subprocess,'CREATE_NO_WINDOW',0)
            subprocess.Popen(['shutdown','/s','/t','60'],creationflags=flags)
            self._shutdown_pending=True; self.cancel_shutdown_btn.show()
            self.db.add_event('Windows запланировала выключение через 60 секунд','WARN')
        except Exception as exc:self.db.add_event(f'Не удалось запланировать выключение: {exc}','ERROR')
        self.refresh_all()
    def cancel_shutdown(self):
        if not self._shutdown_pending:return
        try:
            subprocess.run(['shutdown','/a'],check=False,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            self._shutdown_pending=False; self.cancel_shutdown_btn.hide(); self.db.add_event('Запланированное выключение отменено','INFO'); self.refresh_all()
        except Exception as exc:QMessageBox.warning(self,'Не удалось отменить выключение',str(exc))

    def periodic(self):
        self.watch_folders(); self.update_performance()
        if self.settings.data['schedule_enabled'] and int(time.time())-self._last_report>=int(self.settings.data['schedule_minutes'])*60:
            self._last_report=int(time.time())
            if QMessageBox.question(self,'Плановая проверка','Выполнить запланированную проверку доступности TCP?')==QMessageBox.Yes:self.check_configs()
        if self.settings.data.get('maintenance_enabled'):
            last=self.settings.data.get('last_maintenance','')
            due=not last
            if last:
                try:due=(datetime.now(timezone.utc)-datetime.fromisoformat(last)).days>=int(self.settings.data['maintenance_interval_days'])
                except ValueError:due=True
            if due and not (self.job and self.job.isRunning()):
                if self.create_backup():
                    self.check_integrity(); self.settings.data['last_maintenance']=datetime.now(timezone.utc).isoformat(timespec='seconds'); self.settings.save()
        if self.settings.data.get('auto_shutdown_enabled'):
            today=date.today().isoformat(); current=datetime.now().strftime('%H:%M')
            if current>=self.settings.data.get('auto_shutdown_time','00:00') and self._shutdown_last_date!=today:
                self._shutdown_last_date=today
                if not (self.job and self.job.isRunning()): self.run_shutdown_check()
                else:self.db.add_event('Автовыключение пропущено: в заданное время выполнялась другая задача','WARN')
    def watch_folders(self):
        if not self.settings.data['watch_enabled']:return
        # Ask before each newly discovered/changed file; no silent imports.
        for folder in self.settings.data.get('watch_folders',[]):
            p=Path(folder)
            if not p.is_dir():continue
            for f in p.iterdir():
                if not f.is_file() or f.suffix.lower() not in {'.txt','.json','.yaml','.yml','.csv','.conf','.list','.zip'}:continue
                try: stamp=(f.stat().st_mtime_ns,f.stat().st_size)
                except OSError:continue
                if self._watch_seen.get(str(f))==stamp:continue
                self._watch_seen[str(f)]=stamp
                if QMessageBox.question(self,'Новый файл',f'Обнаружен файл:\n{f}\nИмпортировать?')==QMessageBox.Yes:
                    try:
                        items,errors,digest=read_file(f,self.settings.data['max_file_mb'],self.settings.data['max_archive_unpacked_mb']); self.import_items(items,errors,f.name,digest)
                    except Exception as exc:self.log(f'Ошибка наблюдения за файлом: {exc}','ERROR')
    def exit_app(self):
        self._closing=True
        if self.job and self.job.isRunning():
            if QMessageBox.question(self,'Задача выполняется','Остановить VPNDesk и завершить текущую задачу?')!=QMessageBox.Yes:self._closing=False; return
            self.job.cancel(); self.job.wait(5000)
            if self.job.isRunning():
                QMessageBox.warning(self,'Задача ещё работает','Не удалось безопасно остановить фоновую задачу. Приложение останется открытым.'); self._closing=False; return
        if self.tray:self.tray.hide()
        self.timer.stop()
        if not self._db_closed:self.db.close(); self._db_closed=True
        QApplication.quit()
    def closeEvent(self,event):
        if self.tray and self.settings.data['tray_enabled']:
            self.hide(); self.tray.showMessage('VPNDesk','Программа продолжает работать в системном трее'); event.ignore(); return
        if self.job and self.job.isRunning():
            QMessageBox.information(self,'Задача выполняется','Сначала останови или дождись завершения фоновой задачи.'); event.ignore(); return
        self._closing=True
        self.timer.stop()
        if not self._db_closed:self.db.close(); self._db_closed=True
        event.accept(); QApplication.quit()
