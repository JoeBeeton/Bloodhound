package org.freedonia.bloodhound.server.notification;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

/**
 * Sends one plain-text email (invite, admin-triggered reset, self-serve forgot-password). Same
 * {@code @Async} fire-and-forget shape as {@link SlackNotifier#send}, for the same reason: a
 * slow or unreachable mail relay must never delay the request that triggered the email (a user
 * being created, a password reset being requested). One best-effort attempt per message, no
 * retry - an admin still sees the temporary password in the API response as a fallback for the
 * invite/admin-reset paths (see OrgUserController), and a failed forgot-password email just means
 * the user tries again or an admin resets it for them instead.
 */
@Component
public class EmailSender {

    private static final Logger log = LoggerFactory.getLogger(EmailSender.class);

    private final JavaMailSender mailSender;
    private final String fromAddress;

    public EmailSender(
            JavaMailSender mailSender,
            @Value("${bloodhound.notifications.mail-from-address}") String fromAddress) {
        this.mailSender = mailSender;
        this.fromAddress = fromAddress;
    }

    @Async
    public void send(String to, String subject, String body) {
        attemptDelivery(to, subject, body);
    }

    /** Split out from {@link #send} so a direct, synchronous call can assert on the outcome in a test, same reasoning as SlackNotifier#attemptDelivery. */
    DeliveryResult attemptDelivery(String to, String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(to);
        message.setSubject(subject);
        message.setText(body);
        try {
            mailSender.send(message);
            return DeliveryResult.ok();
        } catch (MailException e) {
            log.warn("email delivery to {} failed: {}", to, e.toString());
            return DeliveryResult.failed(e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    record DeliveryResult(boolean success, String detail) {
        static DeliveryResult ok() {
            return new DeliveryResult(true, null);
        }

        static DeliveryResult failed(String detail) {
            return new DeliveryResult(false, detail);
        }
    }
}
