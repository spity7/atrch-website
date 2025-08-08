import { Swiper, SwiperSlide } from "swiper/react";
import Brand from "../../../components/brand";
import AboutData from "../../../data/global/about.json";

const BrandContainer = () => {
    return (
        <div className="brand-logo-area">
            <div className="container">
                <div className="row">
                    <div className="col-lg-12" data-aos="fade-up">
                        <h2 className="title">{AboutData[6].title}</h2>
                        <p>{AboutData[6].excerpt}</p>
                    </div>
                </div>
                <div className="row">
                    <div
                        className="col-lg-12"
                        data-aos="fade-up"
                        data-aos-delay="300"
                    >
                        <div className="swiper-container brand-logo-slider-container">
                            <Swiper
                                className="brand-logo-slider"
                                spaceBetween={30}
                                slidesPerView={5}
                                loop
                                breakpoints={{
                                    1200: {
                                        slidesPerView: 5,
                                        spaceBetween: 100,
                                    },

                                    992: {
                                        slidesPerView: 4,
                                        spaceBetween: 90,
                                    },

                                    768: {
                                        slidesPerView: 3,
                                        spaceBetween: 110,
                                    },

                                    576: {
                                        slidesPerView: 3,
                                        spaceBetween: 60,
                                    },

                                    320: {
                                        slidesPerView: 2,
                                        spaceBetween: 30,
                                    },
                                }}
                            >
                                {AboutData[6].brand &&
                                    AboutData[6].brand.map((single, key) => {
                                        return (
                                            <SwiperSlide key={key}>
                                                <Brand
                                                    data={single}
                                                    key={key}
                                                />
                                            </SwiperSlide>
                                        );
                                    })}
                            </Swiper>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default BrandContainer;
