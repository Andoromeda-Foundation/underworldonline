/**
 * Created by 黑暗之神KDS on 2019-07-09 15:04:27.
 */

class UIList extends UIRoot {
        /**
         * 事件：打开状态发生改变时 onChange(ui,data)
         */
        static EVENT_OPEN_STATE_CHANGE:string = "UIList_EVENT_OPEN_STATE_CHANGE";

        /**指定是否可以选择，若值为true则可以选择，否则不可以选择。*/
        private _selectEnable: boolean = true;
        /**
         * 水平方向显示的单元格数量。
         */
        private _repeatX: number;
        /**
         * 水平方向显示的单元格之间的间距（以像素为单位）。
         */
        private _spaceX: number;
        /**
         * 垂直方向显示的单元格之间的间距（以像素为单位）。
         */
        private _spaceY: number;
        /**
         * 项的宽度
         */
        private _itemWidth: number;
        /**
         * 项的高度
         */
        private _itemHeight: number;
        /**
         * 选中项数据
         */
        private _selectedItem: UIListItemData;
        /**
         * 选中项索引
         */
        private _selectedIndex: number = -1;
        /**
         * 选中项对象
         */
        private _selectedItemObject: UIComponent.UIRoot;
        /**
         * 设置数据源
         */
        private _items: UIListItemData[] = [];
        /**
         * 创建的类
         */
        private _itemModelClass: any;
        /**
         * 创建的GUI-ID
         */
        private _itemModelGUI: number;
        /**
         * 光标效果
         */
        private _overImageURL: string;
        /**
         * 选中效果
         */
        private _selectImageURL: string;
        /**
         * 光标效果九宫格
         */
        private _overImageGrid9: string;
        /**
         * 选中效果九宫格
         */
        private _selectImageGrid9: string;
        /**
         * 内容区域
         */
        private _contentArea: GameSprite;
        /**
         * 选中效果
         */
        private _selectedImage: UIImage;
        /**
         * 选中效果透明度
         */
        private _selectedImageAlpha: number;
        /**
         * 选中效果是否位于上层
         */
        private _selectedImageOnTop: boolean = true;
        /**
         * 光标效果
         */
        private _overImage: UIImage;
        /**
         * 光标透明度
         */
        private _overImageAlpha: number;
        /**
        * 光标效果是否位于上层
        */
        private _overImageOnTop: boolean = true;
        /**
         * 创建ITEM时回调 onCreateItem(ui: UIRoot, data: UIListItemData)
         */
        onCreateItem: Callback;

        constructor() {
            super();
            this.className = "UIList";
            this._contentArea = new GameSprite();
            this._overImage = new UIImage();
            this._selectedImage = new UIImage();
            this._overImage.visible = false;
            this.refreshLayer();
            this.enabledLimitView = true;
            this.scrollShowType = 2;
            if (Config.EDIT_MODE) {
                Callback.CallLater(this.itemsPreview, this);
            }
        }
        inEditorInit() {
            this._itemWidth = 200;
            this._itemHeight = 50;
            this._spaceX = 2;
            this._spaceY = 20;
            this.overImageURL = "asset/image/picture/UI/dgm_input2.png";
            this.selectImageURL = "asset/image/picture/UI/dgm_input3.png";
            this.selectedImageAlpha = 0.5;
            this.overImageAlpha = 0.5;
        }
        /**
         * 项预览：用于编辑器中预览用
         */
        private itemsPreview() {
            if (!Config.EDIT_MODE || !this.stage) return;
            var arr: UIListItemData[] = [];
            for (var i = 0; i < 50; i++) {
                var d = new UIListItemData();
                arr.push(d);
            }
            this.items = arr;
            this.selectedIndex = 0;
        }
        //------------------------------------------------------------------------------------------------------
        // 常规操作
        //------------------------------------------------------------------------------------------------------
        get selectEnable() {
            return this._selectEnable;
        }
        set selectEnable(v: boolean) {
            if (this._selectEnable != v) {
                this._selectEnable = v;
                this._overImage.visible = v;
            }
        }
        get repeatX() {
            return this._repeatX;
        }
        set repeatX(v: number) {
            if (this._repeatX != v) {
                this._repeatX = v;
                if (this._repeatX < 1) this._repeatX = 1;
                this.refreshOrder()
            }
        }
        get spaceX() {
            return this._spaceX;
        }
        set spaceX(v: number) {
            if (this._spaceX != v) {
                this._spaceX = v;
                this.refreshOrder()
            }
        }
        get spaceY() {
            return this._spaceY;
        }
        set spaceY(v: number) {
            if (this._spaceY != v) {
                this._spaceY = v;
                this.refreshOrder()
            }
        }
        get itemWidth() {
            return this._itemWidth;
        }
        set itemWidth(v: number) {
            if (this._itemWidth != v) {
                this._itemWidth = v;
                if (this._itemWidth < 1) this._itemWidth = 1;
                this.refreshOrder()
            }
        }
        get itemHeight() {
            return this._itemHeight;
        }
        set itemHeight(v: number) {
            if (this._itemHeight != v) {
                this._itemHeight = v;
                if (this._itemHeight < 1) this._itemHeight = 1;
                this.refreshOrder()
            }
        }
        //------------------------------------------------------------------------------------------------------
        // 效果
        //------------------------------------------------------------------------------------------------------
        set overImageURL(v: string) {
            if (this._overImageURL != v) {
                this._overImageURL = v;
                this._overImage.skin = v;
            }
        }
        get overImageURL() {
            return this._overImageURL;
        }
        get overImage() {
            return this._overImage;
        }
        set selectImageURL(v: string) {
            if (this._selectImageURL != v) {
                this._selectImageURL = v;
                this._selectedImage.skin = v;
            }
        }
        get selectImageURL() {
            return this._selectImageURL;
        }
        get selectImage() {
            return this._selectedImage;
        }
        set overImageGrid9(v: string) {
            if (this._overImageGrid9 != v) {
                this._overImageGrid9 = v;
                this._overImage.sizeGrid = v;
            }
        }
        get overImageGrid9() {
            return this._overImageGrid9;
        }
        set selectImageGrid9(v: string) {
            if (this._selectImageGrid9 != v) {
                this._selectImageGrid9 = v;
                this._selectedImage.sizeGrid = v;
            }
        }
        get selectImageGrid9() {
            return this._selectImageGrid9;
        }
        set selectedImageAlpha(v: number) {
            if (this._selectedImageAlpha != v) {
                this._selectedImageAlpha = v;
                this._selectedImage.alpha = v;
            }
        }
        get selectedImageAlpha() {
            return this._selectedImageAlpha;
        }
        set overImageAlpha(v: number) {
            if (this._overImageAlpha != v) {
                this._overImageAlpha = v;
                this._overImage.alpha = v;
            }
        }
        get overImageAlpha() {
            return this._overImageAlpha;
        }

        set selectedImageOnTop(v: boolean) {
            if (this._selectedImageOnTop != v) {
                this._selectedImageOnTop = v;
                this.refreshLayer();
            }
        }
        get selectedImageOnTop() {
            return this._selectedImageOnTop;
        }
        set overImageOnTop(v: boolean) {
            if (this._overImageOnTop != v) {
                this._overImageOnTop = v;
                this.refreshLayer();
            }
        }
        get overImageOnTop() {
            return this._overImageOnTop;
        }
        private refreshLayer() {
            if (!this._selectedImageOnTop) {
                this.addChild(this._selectedImage);
            }
            if (!this._overImageOnTop) {
                this.addChild(this._overImage);
            }
            this.addChild(this._contentArea);
            if (this._selectedImageOnTop) {
                this.addChild(this._selectedImage);
            }
            if (this._overImageOnTop) {
                this.addChild(this._overImage);
            }
        }
        //------------------------------------------------------------------------------------------------------
        // 选中
        //------------------------------------------------------------------------------------------------------

        //------------------------------------------------------------------------------------------------------
        // 源模型设置
        //------------------------------------------------------------------------------------------------------
        get itemModelClass(): any {
            return this._itemModelClass;
        }
        set itemModelClass(v: any) {
            if (this._itemModelClass != v) {
                this._itemModelClass = v;
                this._itemModelGUI = 0;
            }
        }
        get itemModelGUI(): number {
            return this._itemModelGUI;
        }
        set itemModelGUI(v: number) {
            if (this._itemModelGUI != v) {
                this._itemModelGUI = v;
                var uiData = Common.uiList.data[v];
                if (!uiData) {
                    this._itemModelClass = null;
                    this.itemsPreview();
                    return;
                }
                var instanceClassName = uiData.uiDisplayData.instanceClassName;
                var classObj = window[instanceClassName];
                if (!classObj) classObj = window["GUI_" + v];
                this._itemModelClass = classObj;
                this.itemsPreview();
            }
        }
        //------------------------------------------------------------------------------------------------------
        // ITEM 数据操作
        //------------------------------------------------------------------------------------------------------
        /**
         * 设置数据集
         * 根据数据集生成对应的ITEM容器
         * @return [UIListItemData] 
         */
        get items(): UIListItemData[] {
            return this._items;
        }
        set items(v: UIListItemData[]) {
            var lastSelectedItem = this.selectedItem;
            // clear all
            for (var i = 0; i < this._contentArea.numChildren; i++) {
                var item: UIRoot = this._contentArea.getChildAt(i) as any;
                item.dispose();
                i--;
            }
            this._items.length = 0;
            // create all
            if (Config.EDIT_MODE || this._itemModelClass) {
                var len = v.length;
                for (var i = 0; i < len; i++) {
                    var node = v[i];
                    var nodeChildren = node.getList();
                    var childrenlen = nodeChildren.length;
                    for (var s = 0; s < childrenlen; s++) {
                        var data = nodeChildren[s];
                        this._items.push(data);
                        var ui: UIRoot;
                        if (Config.EDIT_MODE) {
                            ui = GameUI.load(this.itemModelGUI, true);
                        }
                        else {
                            ui = new this._itemModelClass(false, this._itemModelGUI);
                        }
                        this._contentArea.addChild(ui);
                        debugger
                        this.itemInit(ui, data);
                    }
                }
                this.refreshOrder();
            }
            // 选中上次选中项
            this.selectedItem = this.selectedItem;
        }
        /**
         * 项初始化
         */
        private itemInit(ui: UIRoot, data: UIListItemData) {
            if(!ui)return;
            // 装载的数据设置
            ui.data = data;
            // over 效果
            ui.on(EventObject.MOUSE_OVER, this, (ui: UIRoot) => {
                this._overImage.x = ui.x;
                this._overImage.y = ui.y;
            }, [ui]);
            // 选中 效果
            ui.on(EventObject.MOUSE_DOWN, this, (ui: UIRoot, data: UIListItemData) => {
                this.selectedItem = data;
            }, [ui, data]);
            // 双击 切换开启效果
            ui.on(EventObject.DOUBLE_CLICK, this, (ui: UIRoot, data: UIListItemData) => {
                data.isOpen = !data.isOpen;
                this.refreshOrder();
                this.event(UIList.EVENT_OPEN_STATE_CHANGE,[ui,data]);
            }, [ui, data]);
            // 设置数据
            this.refreshItem(data);
            // 自定义回调
            this.onCreateItem && this.onCreateItem.runWith([ui, data]);
        }
        /**
         * 刷新数据
         * @param item 
         */
        refreshItem(item: UIListItemData): void {
            var idx = this.items.indexOf(item);
            if (idx == -1) return;
            var ui: UIRoot = this._contentArea.getChildAt(idx) as any;
            var uiNames = item.uiNames;
            for (var i = 0; i < uiNames.length; i++) {
                var attrName = uiNames[i];
                var comp: UIBase = ui[attrName];
                var value = item[attrName];
                if (comp && comp instanceof UIBase && value != null) {
                    switch (comp.className) {
                        case "UIBitmap":
                            debugger
                            (comp as UIBitmap).image = value;
                            break;
                        case "UIString":
                            (comp as UIString).text = value;
                            break;
                        case "UIVariable":
                            (comp as UIVariable).varID = value;
                            break;
                        case "UIAvatar":
                            (comp as UIAvatar).avatarID = value;
                            break;
                        case "UIAnimation":
                            (comp as UIAnimation).animationID = value;
                            break;
                        case "UIInput":
                            (comp as UIInput).text = value;
                            break;
                        case "UICheckBox":
                            (comp as UICheckBox).selected = value;
                            break;
                        case "UISwitch":
                            (comp as UISwitch).switchID = value;
                            break;
                        case "UITabBox":
                            (comp as UITabBox).items = value;
                            break;
                        case "UISlider":
                            (comp as UISlider).value = value;
                            break;
                        case "UIGUI":
                            (comp as UIGUI).guiID = value;
                            break;
                        case "UIList":
                            (comp as UIList).items = value;
                            break;
                    }
                }
            }
        }
        /**
         * 列表的数据总个数。
         */
        get length(): number { return this._items.length };
        //------------------------------------------------------------------------------------------------------
        // ITEM 单体对象操作
        // 左右键单击:选中，CTRL、SHIFT多选
        // mouseover:选中效果
        // 
        //------------------------------------------------------------------------------------------------------
        /**
         * 选中项，根据指定的数据
         * @return [UIListItemData] 
         */
        get selectedItem(): UIListItemData {
            return this._selectedItem;
        }
        set selectedItem(v: UIListItemData) {
            var idx = this._items.indexOf(v);
            this._selectedItem = idx != -1 ? v : null;
            this.selectedIndex = idx;
        }
        /**
         * 选中项，根据索引（即所在数据组的位置，数据组包括未打开的隐藏树节点）
         * @return [number] 
         */
        get selectedIndex(): number {
            return this._selectedIndex;
        }
        set selectedIndex(v: number) {
            if (this._selectedIndex != v) {
                this._selectedIndex = v;
                this.refreshSelectedImagePos();
                this.event(EventObject.CHANGE);
            }
        }
        /**
         * 刷新选中图片位置根据选中项
         */
        private refreshSelectedImagePos() {
            if (this.selectedIndex < 0 || this.selectedIndex >= this._contentArea.numChildren) {
                this._selectedImage.visible = false;
                return;
            }
            var ui: UIRoot = this._contentArea.getChildAt(this.selectedIndex) as any;
            if (!ui) {
                this._selectedImage.visible = false;
                return;
            }
            this._selectedImage.visible = ui.visible;
            this._selectedImage.x = ui.x;
            this._selectedImage.y = ui.y;
        }
        //------------------------------------------------------------------------------------------------------
        // 私有实现
        //------------------------------------------------------------------------------------------------------
        /**
         * 刷新排列
         */
        private refreshOrder() {
            var len = this._contentArea.numChildren;
            for (var i = 0, s = 0; i < len; i++) {
                var ui: UIComponent.UIBase = this._contentArea.getChildAt(i) as any;
                var data = ui.data as UIListItemData;
                if (data.isHideNode) {
                    ui.visible = false;
                    continue;
                }
                ui.visible = true;
                ui.x = (s % this.repeatX) * (this._itemWidth + this._spaceX) + data.depth * 20;
                ui.y = Math.floor(s / this.repeatX) * (this._itemHeight + this._spaceY);
                s++;
            }
            this._overImage.visible = s > 0 && this.selectEnable;
            this._contentArea.width = (this._itemWidth * this.repeatX) + (this._spaceX * this.repeatX - 1);
            this._contentArea.height = Math.ceil(len / this.repeatX) * this._itemHeight + Math.max(0, Math.ceil(len / this.repeatX) - 1) * this._spaceY;
            this._overImage.width = this._itemWidth;
            this._overImage.height = this._itemHeight;
            this._selectedImage.width = this._itemWidth;
            this._selectedImage.height = this._itemHeight;
            this.refreshSelectedImagePos();
            this.refresh();
        }
    }
