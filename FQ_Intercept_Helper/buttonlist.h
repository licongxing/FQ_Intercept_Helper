#ifndef BUTTONLIST_H
#define BUTTONLIST_H

#include <QWidget>

namespace Ui {
class ButtonList;
}

class ButtonList : public QWidget
{
    Q_OBJECT

public:
    explicit ButtonList(QWidget *parent = nullptr);
    ~ButtonList();

public:
    Ui::ButtonList *ui;
};

#endif // BUTTONLIST_H
