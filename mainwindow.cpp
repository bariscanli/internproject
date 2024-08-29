#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    this->setWindowTitle("Login");

    settings = new QSettings("MyApp", "LoginApp", this);

    if (!connectToDatabase()) {
         QMessageBox::critical(this, "Veritabanı Hatası", "Veritabanına bağlanılamadı!");
    }

    this->setStyleSheet("background-color: #ADD8ED;");

    connect(ui->forgotPasswordButton, &QPushButton::clicked, this, &MainWindow::on_forgotPasswordButton_clicked);
    connect(ui->registerButton, &QPushButton::clicked, this, &MainWindow::on_registerButton_clicked);

    // "Remember Me" bilgilerini yükle
    loadRememberedCredentials();
}

MainWindow::~MainWindow()
{
    delete ui;
    db.close();
}

bool MainWindow::connectToDatabase()
{
    db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("newdatabase.db");

    if (!db.open()) {
        return false;
    }

    QSqlQuery query;
    query.exec("CREATE TABLE IF NOT EXISTS users ("
               "id INTEGER PRIMARY KEY AUTOINCREMENT, "
               "username TEXT UNIQUE, "
               "password TEXT, "
               "email TEXT UNIQUE)");

    return true;
}

QString MainWindow::hashPassword(const QString &password)
{
    return QString(QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256).toHex());
}

bool MainWindow::authenticateUser(const QString &username, const QString &password)
{
    QSqlQuery query;
    query.prepare("SELECT password FROM users WHERE username = :username");
    query.bindValue(":username", username);

    if (query.exec() && query.next()) {
        QString storedPassword = query.value(0).toString();
        return storedPassword == hashPassword(password);
    }

    return false;
}

bool MainWindow::userExists(const QString &username, const QString &email)
{
    QSqlQuery query;
    query.prepare("SELECT COUNT(*) FROM users WHERE username = :username OR email = :email");
    query.bindValue(":username", username);
    query.bindValue(":email", email);

    if (query.exec() && query.next()) {
        return query.value(0).toInt() > 0;
    }

    return false;
}

void MainWindow::registerUser(const QString &username, const QString &password, const QString &email)
{
    if (userExists(username, email)) {
        QMessageBox::warning(this, "Kayıt Hatası", "Bu kullanıcı adı veya email zaten alınmış.");
        return;
    }

    QSqlQuery query;
    query.prepare("INSERT INTO users (username, password, email) VALUES (:username, :password, :email)");
    query.bindValue(":username", username);
    query.bindValue(":password", hashPassword(password));
    query.bindValue(":email", email);

    if (!query.exec()) {
        QMessageBox::critical(this, "Kayıt Hatası", "Kayıt işlemi sırasında bir hata oluştu: " + query.lastError().text());
    } else {
        QMessageBox::information(this, "Kayıt Başarılı", "Kayıt işlemi başarılı!");
    }
}

void MainWindow::on_loginButton_clicked()
{
    QString username = ui->usernameLineEdit->text();
    QString password = ui->passwordLineEdit->text();

    if (authenticateUser(username, password)) {
        saveCredentialsIfRemembered();
        QMessageBox::information(this, "Giriş Başarılı", "Giriş başarılı!");
    } else {
        QMessageBox::warning(this, "Giriş Hatası", "Kullanıcı adı veya şifre yanlış.");
    }
}

void MainWindow::on_forgotPasswordButton_clicked()
{
    QString email = QInputDialog::getText(this, "Şifre Sıfırla", "Kayıt olduğunuz email adresini girin:");
    if (!email.isEmpty()) {
        sendResetPasswordEmail(email);
    }
}

void MainWindow::on_registerButton_clicked()
{
    QString newUsername = QInputDialog::getText(this, "Kayıt Ol", "Yeni Kullanıcı Adı:");
    QString newPassword = QInputDialog::getText(this, "Kayıt Ol", "Yeni Şifre:", QLineEdit::Password);
    QString email = QInputDialog::getText(this, "Kayıt Ol", "Email Adresi:");

    if (!newUsername.isEmpty() && !newPassword.isEmpty() && !email.isEmpty()) {
        registerUser(newUsername, newPassword, email);


    } else {
        QMessageBox::warning(this, "Kayıt Hatası", "Tüm alanları doldurmanız gerekiyor.");
    }
}

void MainWindow::sendResetPasswordEmail(const QString &email)
{
    QSqlQuery query;
    query.prepare("SELECT username FROM users WHERE email = :email");
    query.bindValue(":email", email);

    if (query.exec() && query.next()) {
        QString username = query.value(0).toString();
        QString newPassword = "newpassword";
        QString hashedPassword = hashPassword(newPassword);

        query.prepare("UPDATE users SET password = :password WHERE email = :email");
        query.bindValue(":password", hashedPassword);
        query.bindValue(":email", email);

        if (query.exec()) {
            QMessageBox::information(this, "Şifre Gönderildi", "Yeni şifre email adresinize gönderildi." );
        } else {
            QMessageBox::warning(this, "Hata", "Şifre sıfırlama sırasında bir hata oluştu.");
        }
        // Diyalog kutusunu kapatıyoruz
                QInputDialog *resetDialog = qobject_cast<QInputDialog*>(sender());
                if (resetDialog) {
                    resetDialog->close();
                }
    } else {
        QMessageBox::warning(this, "Hata", "Bu email adresiyle kayıtlı kullanıcı bulunamadı.");
    }
}

void MainWindow::loadRememberedCredentials()
{
    QString rememberedUsername = settings->value("username", "").toString();
    QString rememberedPassword = settings->value("password", "").toString();

    if (!rememberedUsername.isEmpty() && !rememberedPassword.isEmpty()) {
        ui->usernameLineEdit->setText(rememberedUsername);
        ui->passwordLineEdit->setText(rememberedPassword);
        ui->rememberBox->setChecked(true);
    }
}

void MainWindow::saveCredentialsIfRemembered()
{
    if (ui->rememberBox->isChecked()) {
        settings->setValue("username", ui->usernameLineEdit->text());
        settings->setValue("password", ui->passwordLineEdit->text());
    } else {
        settings->remove("username");
        settings->remove("password");
    }
}
