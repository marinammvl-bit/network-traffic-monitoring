def calculate_roi():
    print("="*60)
    print("РАСЧЕТ ROI ВНЕДРЕНИЯ СИСТЕМЫ МОНИТОРИНГА")
    print("="*60)
    
    # Вводные данные (примерные, на основе Ponemon Institute)
    cost_of_breach = 4_500_000 # Средняя стоимость утечки данных (руб)
    probability_of_breach = 0.3 # 30% вероятность инцидента без защиты
    expected_loss = cost_of_breach * probability_of_breach
    
    # Эффект от внедрения системы
    risk_reduction = 0.8 # Система снижает риск на 80%
    avoided_loss = expected_loss * risk_reduction
    
    # Затраты на систему (в год)
    system_cost = 500_000 # Лицензии, сервер, зарплата аналитика
    
    # Расчет ROI
    net_profit = avoided_loss - system_cost
    roi = (net_profit / system_cost) * 100
    
    print(f"Ожидаемые потери без защиты: {expected_loss:,.2f} руб.")
    print(f"Предотвращенные потери (с системой): {avoided_loss:,.2f} руб.")
    print(f"Стоимость внедрения и поддержки: {system_cost:,.2f} руб.")
    print("-" * 60)
    print(f"Чистая прибыль (экономия): {net_profit:,.2f} руб.")
    print(f"ROI: {roi:.1f}%")
    
    if roi > 0:
        print("Внедрение системы экономически целесообразно!")
    else:
        print("Внедрение системы убыточно.")

if __name__ == "__main__":
    calculate_roi()