from flask import Flask, request, render_template
import pandas as pd

app = Flask(__name__)

def merge_unique_rows(df):
    # Создадим пустой DataFrame для результата
    result_df = pd.DataFrame(columns=df.columns)

    for plugin_id in df['Plugin ID'].unique():
        # Выберем строки с текущим Plugin ID
        temp_df = df[df['Plugin ID'] == plugin_id]

        # Инициализируем словарь для хранения уникальных значений по каждому столбцу
        merged_data = {col: [] for col in df.columns}

        # Заполним словарь значениями, удаляя переносы строк
        for col in df.columns:
            cleaned_values = set()
            for val in temp_df[col]:
                if pd.notna(val):
                    # Удаляем переносы строк из каждого значения
                    cleaned_val = str(val).replace("\n", " ").replace("\r", " ")
                    cleaned_values.add(cleaned_val)
            merged_data[col] = cleaned_values

        # Преобразуем наборы в строки, разделяя значения 
        for col in merged_data:
            merged_data[col] = "<br/>".join(map(str, merged_data[col]))

        # Добавляем собранную информацию по текущему Plugin ID в результирующий DataFrame
        result_df = pd.concat([result_df, pd.DataFrame([merged_data])], ignore_index=True)

    return result_df

@app.route("/", methods=["GET"])
def index():

    return render_template('index.html')

@app.route("/compare", methods=["POST"])
def compare():
    if 'file1' not in request.files or 'file2' not in request.files:
        return "Two files are required."
    file1 = request.files['file1']
    file2 = request.files['file2']
    if file1.filename == '' or file2.filename == '':
        return "No selected file"
    if file1 and file2:
        df1 = pd.read_csv(file1)
        df2 = pd.read_csv(file2)
        
        # Фильтрация по столбцу Risk
        risks = ["High", "Medium", "Low", "Critical"]
        df1_filtered = df1[df1['Risk'].isin(risks)]
        df2_filtered = df2[df2['Risk'].isin(risks)]
        
        # Сортировка по 'Plugin ID'
        df1_sorted = df1_filtered.sort_values(by='Plugin ID')
        df2_sorted = df2_filtered.sort_values(by='Plugin ID')
        
        # Используем merge с indicator=True и how='right' для идентификации уникальных строк во втором DataFrame
        comparison = pd.merge(df1_sorted, df2_sorted, on=['Plugin ID', 'Host'], how='right', indicator=True)
        unique_to_second = comparison[comparison['_merge'] == 'right_only']
        unique_to_second = merge_unique_rows(unique_to_second)
        
        # Оставляем только нужные поля
        cols_to_keep = ['Plugin ID', 'CVE_y', 'Risk_y', 'Host', 'Protocol_y', 'Port_y', 'Name_y', 'Synopsis_y', 'Description_y', 'Plugin Output_y', 'CVSS v3.0 Base Score_y', 'CVSS v3.0 Temporal Score_y']
        unique_rows_html = unique_to_second[cols_to_keep].to_html(escape=False)
        return render_template('index.html', unique_rows_html=unique_rows_html)

if __name__ == "__main__":
    app.run(debug=True)
