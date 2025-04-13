.PHONY: test cov cov-html lint clean

# Запуск стандартных Django тестов
test:
	python manage.py test

# Запуск тестов с замером покрытия
cov:
	coverage run manage.py test

# Генерация HTML-отчёта покрытия и автоматическое открытие в браузере
cov-html:
	coverage html & disown && start htmlcov/index.html

# Проверка стиля кода (можно заменить на black/isort и т.п.)
lint:
	flake8 authapp tasks

# Очистка отчёта покрытия
clean:
	rd /s /q htmlcov 2>nul || exit 0
	del .coverage 2>nul || exit 0

# .PHONY: test cov cov-html lint clean  # crossystems
#
# # Запуск стандартных Django тестов
# test:
# 	python manage.py test
#
# # Запуск тестов с замером покрытия
# cov:
# 	coverage run manage.py test
#
# # Генерация HTML-отчёта покрытия и автоматическое открытие в браузере
# cov-html:
# 	coverage html
# 	python -m webbrowser htmlcov/index.html
#
# # Проверка стиля кода
# lint:
# 	flake8 authapp tasks
# 	black --check authapp tasks
# 	isort --check-only authapp tasks
#
# # Очистка отчёта покрытия и временных файлов
# clean:
# 	-@rm -rf htmlcov .coverage __pycache__ .pytest_cache
# # -@ предотвращает вывод ошибок при отсутствии файлов
