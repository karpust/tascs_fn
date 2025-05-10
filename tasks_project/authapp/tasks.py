from celery import shared_task
from django.core.mail import send_mail, EmailMultiAlternatives
from django.template.loader import render_to_string


# @shared_task
# def send_email_task(subject, message, from_email, recipient_list):
#     send_mail(subject, message, from_email, recipient_list, fail_silently=False)

@shared_task(bind=True, max_retries=3, default_retry_delay=300)
def send_email_task(self, template_name, context, subject, from_email, recipient_list):
    """
    на выполнение задачи дается 3 попытки,
    интервал между попытками 5 мин.
    """
    try:
        text_content = render_to_string(f'emails/{template_name}.txt', context)
        html_content = render_to_string(f'emails/{template_name}.html', context)

        msg = EmailMultiAlternatives(subject, text_content, from_email, recipient_list)
        msg.attach_alternative(html_content, "text/html")
        print(f'msg.recipients() = {msg.recipients()}')
        print(f'msg.body = {msg.body}')  # текстовая часть
        print(f'msg.alternatives = {msg.alternatives}')  # список с html: [(html_content, 'text/html')]
        msg.send()

    except Exception as e:
        raise self.retry(exc=e)

    # send_mail(subject, message, from_email, recipient_list, fail_silently=False)


