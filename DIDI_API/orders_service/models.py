from sqlalchemy import Column, Integer, String, Float
from database import Base

class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)

    product_id = Column(Integer, nullable=False)
    product_name = Column(String, nullable=False)
    product_price = Column(Float, nullable=False)
    product_description = Column(String)
    quantity = Column(Integer, nullable=False)
    total = Column(Float, nullable=False)
