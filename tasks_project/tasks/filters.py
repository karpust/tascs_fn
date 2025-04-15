import django_filters
from django.db.models import Q
from .models import Task

"""
В API предусмотрена система фильтрации задач по ключевым параметрам:
status – фильтрация по статусу задачи (например: todo, in_progress, done).
priority – по приоритету (low, medium, high).
executor – по назначенному пользователю (ID пользователя).
owner – по создателю задачи (ID пользователя).
--is_done – фильтрация по признаку завершённости (true / false).
created_after, created_before – по дате создания (формат: YYYY-MM-DD).
due_after, due_before – по сроку дедлайна.
search – текстовый поиск по названию и описанию задачи.

сортировка (ordering) по:
created_at – дате создания,
priority – приоритету,
title – названию.
"""


class TaskFilter(django_filters.FilterSet):
    created_after = django_filters.DateFilter(field_name="created_at", lookup_expr="gte")
    created_before = django_filters.DateFilter(field_name="created_at", lookup_expr="lte")
    due_after = django_filters.DateFilter(field_name="due_date", lookup_expr="gte")
    due_before = django_filters.DateFilter(field_name="due_date", lookup_expr="lte")
    # has_due_date = django_filters.BooleanFilter(method='filter_has_due_date')
    search = django_filters.CharFilter(method='filter_search')

    class Meta:
        model = Task
        fields = [
            'status',
            'priority',
            'executor',
            'owner',
        ]

    # def filter_has_due_date(self, queryset, name, value):
    #     if value:
    #         return queryset.exclude(due_date__isnull=True)
    #     return queryset.filter(due_date__isnull=True)

    def filter_search(self, queryset, name, value):
        return queryset.filter(
            Q(title__icontains=value) | Q(description__icontains=value)
        )

"""

class TaskViewSet(ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_class = TaskFilter
    ordering_fields = ['created_at', 'due_date', 'priority', 'title']
    ordering = ['-created_at']  # дефолтная сортировка
"""