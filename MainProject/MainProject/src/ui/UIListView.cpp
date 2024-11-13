#include "../../include/ui/UIListView.h"

void UIListView::AddColumns(const wchar_t* columnsHeaders[], int columnsCount) {
    LVCOLUMN lvColumn;
    lvColumn.mask = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;

    for (int i = 0; i < columnsCount; i++) {
        lvColumn.cx = DEFAULT_LISTVIEW_COLUMN_WIDTH;
        lvColumn.pszText = const_cast<LPWSTR>(columnsHeaders[i]);  
        ListView_InsertColumn(GetHWindow(), i, &lvColumn);
    }

    _columnsCount = columnsCount;  
}

void UIListView::AddRow(const wchar_t* columnsValues[]) {
    LVITEM lvItem;
    lvItem.mask = LVIF_TEXT;
    lvItem.iItem = ListView_GetItemCount(GetHWindow()); 
    lvItem.iSubItem = 0;
    lvItem.pszText = const_cast<LPWSTR>(columnsValues[0]);
    ListView_InsertItem(GetHWindow(), &lvItem);
    
    for (int i = 1; i < _columnsCount; i++) {
        ListView_SetItemText(GetHWindow(), lvItem.iItem, i, const_cast<LPWSTR>(columnsValues[i]))
    }
}

void UIListView::ClearColumns() {
    while (ListView_DeleteColumn(GetHWindow(), 0)) {}
    _columnsCount = 0;
}
