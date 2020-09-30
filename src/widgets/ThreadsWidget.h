#pragma once

#include <QJsonObject>
#include <memory>
#include <QStandardItem>
#include <QTableView>
#include <QSortFilterProxyModel>

#include "core/Cutter.h"
#include "CutterDockWidget.h"

#include <QAbstractListModel>
#include "AddressableItemModel.h"

class MainWindow;

namespace Ui {
class ThreadsWidget;
}


struct thread_info {
    QString pid;
    QString status;
    QString path;
    bool current;
};

class ThreadModel2: public QStandardItemModel
{
    Q_OBJECT

    //friend MemoryMapWidget;

    enum ColumnIndex {
        COLUMN_PID = 0,
        COLUMN_STATUS,
        COLUMN_PATH,
        ColumnCount
    };

    QVector<thread_info> threaddata;


public:

    void set_data(const QVector<thread_info> d)
    {
        beginResetModel();
        threaddata = d;
        endResetModel();
    }
    void clear_data()
    {
        beginResetModel();
        threaddata.clear();
        endResetModel();
    }

    explicit ThreadModel2(QObject *parent = nullptr) : QStandardItemModel(parent)
    {

    }

    int rowCount(const QModelIndex &parent = QModelIndex()) const override
    {
        Q_UNUSED(parent)
        return threaddata.size();
    }
    int columnCount(const QModelIndex &parent = QModelIndex()) const override
    {
        Q_UNUSED(parent)
        return ColumnIndex::ColumnCount;
    }

    QVariant data(const QModelIndex &index, int role) const override
    {
        if (index.row() >= threaddata.count())
            return QVariant();

        const thread_info d = threaddata.at(index.row());

        switch (role) {
        case Qt::DisplayRole:
            switch (index.column()) {
            case COLUMN_PID:
                return d.pid;
            case COLUMN_STATUS:
                return d.status;
            case COLUMN_PATH:
                return d.path;
            default:
                return QVariant();
            }
        case Qt::FontRole:
            {
                QFont font;// = QStandardItemModel::data(index, role).value<QFont>();
                font.setBold(true);
                return font;
            }
        default:
            return QVariant();
        }
    }
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override
    {
        Q_UNUSED(orientation)

        switch (role) {
        case Qt::DisplayRole:
            switch (section) {
            case COLUMN_PID:
                return tr("Pid");
            case COLUMN_STATUS:
                return tr("Status");
            case COLUMN_PATH:
                return tr("Path");
            default:
                return QVariant();
            }
        default:
            return QVariant();
        }

        return QVariant();
    }
};




class ThreadsFilterModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    ThreadsFilterModel(QObject *parent = nullptr);

protected:
    bool filterAcceptsRow(int row, const QModelIndex &parent) const override;
};

class ThreadsWidget : public CutterDockWidget
{
    Q_OBJECT

public:
    explicit ThreadsWidget(MainWindow *main);
    ~ThreadsWidget();

private slots:
    void updateContents();
    void setThreadsGrid();
    void fontsUpdatedSlot();
    void onActivated(const QModelIndex &index);

private:
    ThreadModel2* m2;
    QString translateStatus(QString status);
    std::unique_ptr<Ui::ThreadsWidget> ui;
    QStandardItemModel *modelThreads;
    ThreadsFilterModel *modelFilter;
    RefreshDeferrer *refreshDeferrer;
};
