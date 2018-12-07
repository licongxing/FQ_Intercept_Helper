#include "buttonlist.h"
#include "ui_buttonlist.h"

ButtonList::ButtonList(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ButtonList)
{
    ui->setupUi(this);
}

ButtonList::~ButtonList()
{
    delete ui;
}
