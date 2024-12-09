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
    HWND hListView = GetHWindow();
    
    LVITEM lvItem;
    lvItem.mask = LVIF_TEXT;
    lvItem.iItem = ListView_GetItemCount(hListView); 
    lvItem.iSubItem = 0;
    lvItem.pszText = const_cast<LPWSTR>(columnsValues[0]);
    ListView_InsertItem(hListView, &lvItem);
    
    for (int i = 1; i < _columnsCount; i++) {
        ListView_SetItemText(hListView, lvItem.iItem, i, const_cast<LPWSTR>(columnsValues[i]))
    }
}

void UIListView::ClearColumns() {
    while (ListView_DeleteColumn(GetHWindow(), 0)) {}
    _columnsCount = 0;
}

boolean UIListView::isScrolledDown() {
    HWND hListView = GetHWindow();
    int itemCount = ListView_GetItemCount(hListView);

    if (itemCount > 0) {
        int topIndex = ListView_GetTopIndex(hListView);
        
        int countPerPage = ListView_GetCountPerPage(hListView);
        
        if (topIndex + countPerPage >= itemCount) {
            return true;
        }
    }

    return false;
}

void UIListView::ScrollDown() {
    HWND hListView = GetHWindow();
    int itemCount = ListView_GetItemCount(hListView);
    if (itemCount > 0) {
        ListView_EnsureVisible(hListView, itemCount - 1, FALSE);
    }
}
