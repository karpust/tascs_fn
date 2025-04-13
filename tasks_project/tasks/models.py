from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import models
User = get_user_model()


class Category(models.Model):
    name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.name


class Tag(models.Model):
    name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.name


class Task(models.Model):

    STATUS_CHOICES = [
        ('to_do', 'To Do'),
        ('in_progress', 'In Progress'),
        ('done', 'Done'),
    ]

    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]

    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='to_do')
    deadline = models.DateTimeField()
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='medium')
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='task_owner')
    executor = models.ManyToManyField(User, related_name='task_executors')
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    # не все задачи могут принадлежать к категории -
    # можно сначала создать задачу без категории, а потом добавить её.
    # если удалить категорию, задачи останутся, но их category станет NULL
    # в некоторых случаях может быть не нужно указывать категорию, а только название задачи.
    tags = models.ManyToManyField(Tag, blank=True)  # поле может быть пустым
    # для ManyToManyField не имеет смысла использовать null=True,
    # потому что это поле не хранит данные в базе напрямую.
    # Связи в ManyToManyField хранятся в отдельной таблице
    # для связи, которая автоматически управляется Django.
    # Даже если не будет выбран ни один тег, таблица связи
    # просто не будет содержать записей для этой модели.

    def clean(self):
        """Проверяем, чтобы был хотя бы один исполнитель"""
        # отсутствие связей в M2M не блокирует создание объекта модели,
        # это нужно проверять вручную;
        super().clean()
        if not self.executor.exists():
            raise ValidationError({'executor': 'This field cannot be null. Need to choose at least one executor.'})

    def __str__(self):
        return self.title


class Comment(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name="comments")
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name="comment_author")
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Comment by {self.author} on {self.task}"


