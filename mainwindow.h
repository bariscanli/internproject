#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QCryptographicHash>
#include <QInputDialog>
#include <QSettings>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_loginButton_clicked();
    void on_forgotPasswordButton_clicked();
    void on_registerButton_clicked();

private:
    Ui::MainWindow *ui;
    QSqlDatabase db;
    QSettings *settings;

    bool connectToDatabase();
    QString hashPassword(const QString &password);
    void sendResetPasswordEmail(const QString &email);
    bool authenticateUser(const QString &username, const QString &password);
    bool userExists(const QString &username, const QString &email);
    void registerUser(const QString &username, const QString &password, const QString &email);
    void loadRememberedCredentials();
    void saveCredentialsIfRemembered();
};

#endif // MAINWINDOW_H
